"""SQLite entity master-data warehouse (human-adjudicated identity merging).

One warehouse is bound to exactly one exported projection *package* and never
switches packages.  It keeps:

* an immutable copy of the package-derived entity base table and relationship
  draft (only Indicator/Malware entities and Relationship rows that pass the
  strict endpoint/body checks participate);
* an adjudication ledger (``same`` / ``different``) whose only authority is a
  human batch — aliases are never guessed;
* four versioned logical tables (entity map, merged relations, contribution
  detail, active verdicts with results/blocking evidence);
* a per-revision change feed computed strictly from before/after row diffs.

Post-build batches never reopen the package, never recompute the whole graph
and never full-scan a result table: only the region reachable from the changed
endpoints through effective ``same`` candidates (blocked ones included) is
recomputed.  Every SQL access goes through the instrumented connection factory
so tests can prove the access scope (filtered/indexed vs. full scan) and do
not have to infer it from wall time or row counts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone

from .util import SGError

# Logical table names (also used as stable identifiers in the change feed).
T_ENTITY = "entity_map"
T_REL = "relations"
T_CONTRIB = "contributions"
T_VERDICT = "verdicts"
TABLE_ORDER = (T_ENTITY, T_REL, T_CONTRIB, T_VERDICT)

ENTITY_TYPES = ("indicator", "malware")
PROJECTION_SCHEMA_TAG = "stix-gate-projection/1"

# Fault-injection hook: when set in the environment, a batch write performs all
# of its row writes and then aborts immediately before COMMIT, proving that
# reopening the warehouse exposes the complete old revision only.
FAULT_ENV = "SG_MASTER_FAULT"

SCHEMA = """
CREATE TABLE package_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE base_objects (
    obj_id       TEXT PRIMARY KEY,
    obj_type     TEXT NOT NULL,
    modified_key INTEGER NOT NULL,
    modified_raw TEXT NOT NULL
);
CREATE TABLE base_edges (
    relationship_id   TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    modified_key      INTEGER NOT NULL,
    modified_raw      TEXT NOT NULL
);
CREATE INDEX ix_base_edges_src ON base_edges(source_id);
CREATE INDEX ix_base_edges_tgt ON base_edges(target_id);

CREATE TABLE adjudications (
    verdict_id         TEXT PRIMARY KEY,
    kind               TEXT NOT NULL,
    endpoint_a         TEXT NOT NULL,
    endpoint_b         TEXT NOT NULL,
    priority           INTEGER,
    status             TEXT NOT NULL,
    updated_in_batch   TEXT NOT NULL,
    updated_revision   INTEGER NOT NULL
);
CREATE INDEX ix_adj_a ON adjudications(endpoint_a);
CREATE INDEX ix_adj_b ON adjudications(endpoint_b);
CREATE INDEX ix_adj_lookup ON adjudications(status, kind, endpoint_a, endpoint_b);

CREATE TABLE batch_receipts (
    batch_id           TEXT PRIMARY KEY,
    input_digest       TEXT NOT NULL,
    input_size         INTEGER NOT NULL,
    expected_parent    INTEGER NOT NULL,
    received_revision  INTEGER NOT NULL,
    published_revision INTEGER NOT NULL,
    applied_at         TEXT NOT NULL,
    operation_count    INTEGER NOT NULL,
    change_count       INTEGER NOT NULL
);
CREATE TABLE revisions (
    revision        INTEGER PRIMARY KEY,
    parent_revision INTEGER,
    batch_id        TEXT,
    created_at      TEXT NOT NULL,
    change_count    INTEGER NOT NULL,
    note            TEXT NOT NULL
);

-- The four logical tables, always reflecting the head revision.
CREATE TABLE t1_entity_map (
    obj_id       TEXT PRIMARY KEY,
    obj_type     TEXT NOT NULL,
    canonical_id TEXT NOT NULL
);
CREATE INDEX ix_t1_canon ON t1_entity_map(canonical_id);

CREATE TABLE t2_relations (
    row_key            TEXT PRIMARY KEY,
    source_canon       TEXT NOT NULL,
    relationship_type  TEXT NOT NULL,
    target_canon       TEXT NOT NULL,
    contribution_count INTEGER NOT NULL,
    is_self_loop       INTEGER NOT NULL
);
CREATE INDEX ix_t2_triple ON t2_relations(source_canon, relationship_type, target_canon);

CREATE TABLE t3_contributions (
    relationship_id   TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    source_canon     TEXT NOT NULL,
    target_canon     TEXT NOT NULL,
    row_key           TEXT NOT NULL,
    is_self_loop      INTEGER NOT NULL,
    modified_key      INTEGER NOT NULL,
    modified_raw      TEXT NOT NULL
);
CREATE INDEX ix_t3_row_key ON t3_contributions(row_key);
CREATE INDEX ix_t3_src ON t3_contributions(source_id);
CREATE INDEX ix_t3_tgt ON t3_contributions(target_id);

CREATE TABLE t4_verdicts (
    verdict_id           TEXT PRIMARY KEY,
    kind                 TEXT NOT NULL,
    endpoint_a           TEXT NOT NULL,
    endpoint_b           TEXT NOT NULL,
    priority             INTEGER,
    result               TEXT NOT NULL,
    blocking_verdict_id  TEXT
);
CREATE INDEX ix_t4_a ON t4_verdicts(endpoint_a);
CREATE INDEX ix_t4_b ON t4_verdicts(endpoint_b);

CREATE TABLE changes (
    change_seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    revision        INTEGER NOT NULL,
    parent_revision INTEGER NOT NULL,
    table_name      TEXT NOT NULL,
    row_key         TEXT NOT NULL,
    op              TEXT NOT NULL,
    row_json        TEXT
);
CREATE INDEX ix_changes_rev ON changes(revision, table_name, row_key);
"""

# Column tuples double as the documented, stable row shapes.
T1_COLS = ("obj_id", "obj_type", "canonical_id")
T2_COLS = ("row_key", "source_canon", "relationship_type", "target_canon",
           "contribution_count", "is_self_loop")
T3_COLS = ("relationship_id", "source_id", "target_id", "relationship_type",
           "source_canon", "target_canon", "row_key", "is_self_loop",
           "modified_key", "modified_raw")
T4_COLS = ("verdict_id", "kind", "endpoint_a", "endpoint_b", "priority",
           "result", "blocking_verdict_id")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ----------------------------------------------------------- instrumentation ----

_SCAN_RE = re.compile(r"^\s*(SELECT|INSERT|REPLACE|UPDATE|DELETE)\b", re.I)
_WHERE_RE = re.compile(r"\bWHERE\b", re.I)
_TABLE_RE = re.compile(
    r"\b(base_objects|base_edges|adjudications|batch_receipts|revisions|"
    r"t1_entity_map|t2_relations|t3_contributions|t4_verdicts|changes|package_meta)\b")


class InstrumentedConnection(sqlite3.Connection):
    """sqlite connection counting filtered vs. full-scan data accesses.

    ``acct`` maps phase -> table -> {"filtered": n, "scan": n, "write": n}.
    Reads without a WHERE clause are ``scan`` (forbidden on the eight data
    tables after build); keyed reads are ``filtered``; targeted DML is
    ``write`` and never counts as a scan.  Post-build batch work must never
    record a ``scan`` against base/result tables.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.row_factory = sqlite3.Row
        self.busy_timeout = 10000
        self.acct = {}
        self._phase = "default"

    def set_phase(self, phase: str):
        self._phase = phase

    def reset_acct(self):
        self.acct = {}

    def access_snapshot(self) -> dict:
        return json.loads(json.dumps(self.acct))

    def _record(self, sql: str):
        m = _SCAN_RE.match(sql)
        if not m:
            return
        verb = m.group(1).upper()
        if verb == "SELECT":
            kind = "scan" if not _WHERE_RE.search(sql) else "filtered"
        else:
            kind = "write"
        for table in set(_TABLE_RE.findall(sql)):
            self.acct.setdefault(self._phase, {}).setdefault(
                table, {"filtered": 0, "scan": 0, "write": 0})[kind] += 1

    def execute(self, sql, parameters=()):
        self._record(sql)
        return super().execute(sql, parameters)

    def executemany(self, sql, parameters):
        self._record(sql)
        return super().executemany(sql, parameters)


def connect(path: str) -> InstrumentedConnection:
    if not os.path.exists(path):
        raise SGError("master-missing", "no master warehouse at that path; run master-build first")
    return sqlite3.connect(path, factory=InstrumentedConnection)


# ------------------------------------------------------------------- helpers ----

def _row_key(source_canon: str, relationship_type: str, target_canon: str) -> str:
    """Stable logical key of a merged directed relation row."""
    return json.dumps([source_canon, relationship_type, target_canon],
                      separators=(",", ":"), ensure_ascii=False)


def _canon_pair(a: str, b: str) -> tuple:
    # UTF-8 byte order equals Python code-point order for valid unicode text.
    return (a, b) if a <= b else (b, a)


def _placeholders(values) -> str:
    return ",".join("?" for _ in values)


class _DSU:
    def __init__(self, members):
        self.parent = {m: m for m in members}

    def find(self, x):
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != x:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        # deterministic internal tie-break; canonical ids are recomputed from
        # the byte-minimum member afterwards, never taken from the tree root.
        if ra > rb:
            ra, rb = rb, ra
        self.parent[rb] = ra


# --------------------------------------------------------------- master build ----

def _open_package(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        raise SGError("file-not-found", "a required input file is missing")
    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError:
        raise SGError("invalid-package", "package is not a readable SQLite database")
    required = {"objects", "edges", "meta"}
    if not required <= names:
        conn.close()
        raise SGError("invalid-package", "package is not a sealed STIX gate projection")
    tag = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
    if tag is None or tag[0] != PROJECTION_SCHEMA_TAG:
        conn.close()
        raise SGError("invalid-package", "package schema tag is not recognized")
    try:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.DatabaseError:
        ok = None
    if ok != "ok":
        conn.close()
        raise SGError("integrity-failure", "package fails integrity check")
    return conn


def build_master(package_path: str, master_path: str) -> dict:
    """Create the revision-0 warehouse from one sealed projection package.

    The package is streamed once, sequentially; the warehouse is written to a
    temp file and atomically renamed.  An existing warehouse is never replaced
    and a warehouse never changes its package.
    """
    if os.path.exists(master_path):
        raise SGError("master-exists",
                      "a master warehouse already exists at that path; one warehouse binds one package")
    pkg = _open_package(package_path)
    try:
        file_digest = hashlib.sha256()
        with open(package_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                file_digest.update(chunk)
        meta = {r["key"]: r["value"] for r in pkg.execute("SELECT key, value FROM meta")}

        out_dir = os.path.dirname(os.path.abspath(master_path))
        tmp_fd, tmp_path = _temp_path(out_dir, master_path)
        os.close(tmp_fd)
        conn = sqlite3.connect(tmp_path, factory=InstrumentedConnection)
        conn.set_phase("build")
        try:
            conn.executescript(SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            # ---- package provenance (summary + context) ----
            provenance = dict(meta)
            provenance["package_digest_sha256"] = file_digest.hexdigest()
            provenance["package_size_bytes"] = str(os.path.getsize(package_path))
            provenance["warehouse_schema"] = "stix-gate-master/1"
            # Per-instance identity: two warehouses built from the same package
            # are still distinct warehouses (e.g. for pagination-token binding).
            provenance["warehouse_instance_id"] = os.urandom(16).hex()
            provenance["built_at"] = _now()
            conn.executemany("INSERT INTO package_meta(key, value) VALUES(?,?)",
                             sorted(provenance.items()))

            # ---- entity base table: Indicator / Malware projection rows ----
            n_ent = 0
            entities = set()
            obj_types = {}
            rows = pkg.execute(
                "SELECT obj_id, obj_type, modified_key, modified_raw FROM objects"
                " WHERE obj_type IN (?,?) ORDER BY obj_id",
                ENTITY_TYPES).fetchall()
            for r in rows:
                conn.execute(
                    "INSERT INTO base_objects(obj_id, obj_type, modified_key, modified_raw)"
                    " VALUES(?,?,?,?)",
                    (r["obj_id"], r["obj_type"], r["modified_key"], r["modified_raw"]))
                entities.add(r["obj_id"])
                obj_types[r["obj_id"]] = r["obj_type"]
                # revision 0: every entity maps to itself even with no verdicts.
                conn.execute(
                    "INSERT INTO t1_entity_map(obj_id, obj_type, canonical_id)"
                    " VALUES(?,?,?)",
                    (r["obj_id"], r["obj_type"], r["obj_id"]))
                n_ent += 1

            # ---- relationship draft: edges cross-checked against bodies ----
            n_edge = n_skip = 0
            aggregates = {}  # row_key -> [contribution rows]
            for e in pkg.execute("SELECT * FROM edges ORDER BY relationship_id").fetchall():
                if e["source_id"] not in entities or e["target_id"] not in entities:
                    n_skip += 1
                    continue
                body_row = pkg.execute(
                    "SELECT doc_json, modified_key, modified_raw FROM objects"
                    " WHERE obj_id=? AND obj_type='relationship'",
                    (e["relationship_id"],)).fetchone()
                if body_row is None:
                    n_skip += 1
                    continue
                try:
                    body = json.loads(body_row["doc_json"])
                except json.JSONDecodeError:
                    n_skip += 1
                    continue
                if not isinstance(body, dict):
                    n_skip += 1
                    continue
                if body.get("source_ref") != e["source_id"] or \
                        body.get("target_ref") != e["target_id"]:
                    n_skip += 1
                    continue
                rel_type = body.get("relationship_type")
                if not isinstance(rel_type, str) or not rel_type:
                    n_skip += 1
                    continue
                rk = _row_key(e["source_id"], rel_type, e["target_id"])
                self_loop = 1 if e["source_id"] == e["target_id"] else 0
                conn.execute(
                    "INSERT INTO base_edges(relationship_id, source_id, target_id,"
                    " relationship_type, modified_key, modified_raw)"
                    " VALUES(?,?,?,?,?,?)",
                    (e["relationship_id"], e["source_id"], e["target_id"], rel_type,
                     body_row["modified_key"], body_row["modified_raw"]))
                conn.execute(
                    "INSERT INTO t3_contributions(relationship_id, source_id, target_id,"
                    " relationship_type, source_canon, target_canon, row_key,"
                    " is_self_loop, modified_key, modified_raw)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (e["relationship_id"], e["source_id"], e["target_id"], rel_type,
                     e["source_id"], e["target_id"], rk, self_loop,
                     body_row["modified_key"], body_row["modified_raw"]))
                aggregates.setdefault(rk, []).append(
                    (e["source_id"], rel_type, e["target_id"]))
                n_edge += 1

            for rk in sorted(aggregates):
                s, rel, t = aggregates[rk][0]
                conn.execute(
                    "INSERT INTO t2_relations(row_key, source_canon, relationship_type,"
                    " target_canon, contribution_count, is_self_loop)"
                    " VALUES(?,?,?,?,?,?)",
                    (rk, s, rel, t, len(aggregates[rk]), 1 if s == t else 0))

            conn.execute(
                "INSERT INTO revisions(revision, parent_revision, batch_id, created_at,"
                " change_count, note) VALUES(0, NULL, NULL, ?, 0, 'build')",
                (_now(),))
            conn.execute(
                "INSERT INTO package_meta(key, value) VALUES('base_entity_count',?)",
                (str(n_ent),))
            conn.execute(
                "INSERT INTO package_meta(key, value) VALUES('base_edge_count',?)",
                (str(n_edge),))
            conn.execute(
                "INSERT INTO package_meta(key, value) VALUES('rejected_edge_count',?)",
                (str(n_skip),))
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        conn.close()
        os.replace(tmp_path, master_path)
    finally:
        pkg.close()
    return {"master": master_path, "status": "sealed", "revision": 0,
            "package_digest_sha256": file_digest.hexdigest()}


def _temp_path(out_dir, final_path):
    import tempfile
    return tempfile.mkstemp(suffix=".sqlite.tmp",
                            prefix=os.path.basename(final_path) + ".",
                            dir=out_dir)


# --------------------------------------------------------- batch parsing/validation

def _generic_batch_error():
    # One content-free code for every structural/semantic batch problem:
    # endpoint identities and why an endpoint is missing are never echoed.
    return SGError("batch-rejected", "the adjudication batch is not valid")


def _load_batch(raw_bytes: bytes) -> dict:
    try:
        doc = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise _generic_batch_error()
    if not isinstance(doc, dict):
        raise _generic_batch_error()
    batch_id = doc.get("batch_id")
    parent = doc.get("expected_parent")
    ops = doc.get("operations")
    if not isinstance(batch_id, str) or not batch_id:
        raise _generic_batch_error()
    if isinstance(parent, bool) or not isinstance(parent, int) or parent < 0:
        raise _generic_batch_error()
    if not isinstance(ops, list):
        raise _generic_batch_error()
    return doc


def _validate_and_stage(conn, doc):
    """Validate against current ledger/base tables; return staged new rows.

    Returns ``(effective, touched)`` where ``effective`` maps verdict_id to the
    new ledger row dict (or None for a retraction) and ``touched`` is the set
    of verdict ids appearing in the batch.
    """
    ops = doc["operations"]
    seen_ids = set()
    parsed = []
    for op in ops:
        if not isinstance(op, dict):
            raise _generic_batch_error()
        action = op.get("op")
        vid = op.get("verdict_id")
        if not isinstance(vid, str) or not vid:
            raise _generic_batch_error()
        if vid in seen_ids:
            raise _generic_batch_error()  # one verdict id once per batch
        seen_ids.add(vid)
        if action == "retract":
            parsed.append(("retract", vid, None))
        elif action == "put":
            kind = op.get("kind")
            a, b = op.get("a"), op.get("b")
            if kind not in ("same", "different"):
                raise _generic_batch_error()
            if not isinstance(a, str) or not isinstance(b, str) or a == b:
                raise _generic_batch_error()
            priority = op.get("priority")
            if kind == "same":
                if isinstance(priority, bool) or not isinstance(priority, int):
                    raise _generic_batch_error()
            elif priority is not None:
                raise _generic_batch_error()
            parsed.append(("put", vid, {"kind": kind, "a": a, "b": b,
                                        "priority": priority}))
        else:
            raise _generic_batch_error()

    current = {}
    id_marks = _placeholders(seen_ids)
    for r in conn.execute(
            "SELECT * FROM adjudications"
            f" WHERE verdict_id IN ({id_marks})", sorted(seen_ids)).fetchall():
        current[r["verdict_id"]] = r
    effective = {}
    for action, vid, payload in parsed:
        if action == "retract":
            row = current.get(vid)
            if row is None or row["status"] != "active":
                raise _generic_batch_error()  # unknown / already retracted
            effective[vid] = None
            continue
        a, b = payload["a"], payload["b"]
        # endpoint existence and same-type checks; both failures look identical
        endpoints = conn.execute(
            "SELECT obj_id, obj_type FROM base_objects WHERE obj_id IN (?,?)",
            (a, b)).fetchall()
        if len(endpoints) != 2:
            raise _generic_batch_error()
        types = {r["obj_type"] for r in endpoints}
        if len(types) != 1:
            raise _generic_batch_error()
        ca, cb = _canon_pair(a, b)
        effective[vid] = {
            "verdict_id": vid, "kind": payload["kind"],
            "endpoint_a": ca, "endpoint_b": cb,
            "priority": payload["priority"], "status": "active"}
    return effective, seen_ids, current


# ------------------------------------------------------------- region discovery

def _same_adjacency(conn, seeds):
    """BFS over effective ``same`` adjacency, using indexed lookups only.

    Blocked ``same`` verdicts stay in the ledger and therefore still define
    reachability: a region includes every candidate that could matter before
    or after the change.  The loop never issues a table-wide scan.
    """
    region = set()
    frontier = set(seeds)
    while frontier:
        batch = sorted(frontier)
        frontier.clear()
        marks = _placeholders(batch)
        rows = conn.execute(
            "SELECT endpoint_a, endpoint_b FROM adjudications"
            " WHERE status='active' AND kind='same' AND ("
            f"endpoint_a IN ({marks}) OR endpoint_b IN ({marks}))",
            batch + batch).fetchall()
        for r in rows:
            for node in (r["endpoint_a"], r["endpoint_b"]):
                if node not in region:
                    region.add(node)
                    frontier.add(node)
    return region


# --------------------------------------------------------------- local recompute

def _recompute_region(conn, region, effective):
    """Recompute groups, T4 results and mapping for one closed region.

    The post-batch ledger has already been persisted by the caller, so the
    SQL below reads the new effective set directly.  Region membership is
    closed under same-adjacency, making the local result identical to a
    whole-graph run.  ``effective`` is only used to keep staged retractions
    out of the active result set.
    """
    marks = _placeholders(region)
    region_list = sorted(region)
    same_rows = [dict(r) for r in conn.execute(
        "SELECT verdict_id, endpoint_a, endpoint_b, priority FROM adjudications"
        f" WHERE status='active' AND kind='same' AND endpoint_a IN ({marks})"
        f" AND endpoint_b IN ({marks})",
        region_list + region_list).fetchall()]
    diff_rows = [dict(r) for r in conn.execute(
        "SELECT verdict_id, endpoint_a, endpoint_b FROM adjudications"
        f" WHERE status='active' AND kind='different' AND endpoint_a IN ({marks})"
        f" AND endpoint_b IN ({marks})",
        region_list + region_list).fetchall()]

    # priority desc, then verdict id UTF-8 byte asc.
    same_rows.sort(key=lambda r: (-r["priority"], r["verdict_id"]))
    diff_rows.sort(key=lambda r: r["verdict_id"])

    dsu = _DSU(region)
    t4_results = {}
    for s in same_rows:
        ra, rb = dsu.find(s["endpoint_a"]), dsu.find(s["endpoint_b"])
        if ra == rb:
            t4_results[s["verdict_id"]] = ("already-same", None)
            continue
        blocker = None
        for d in diff_rows:
            x, y = dsu.find(d["endpoint_a"]), dsu.find(d["endpoint_b"])
            if x != y and {x, y} == {ra, rb}:
                blocker = d["verdict_id"]  # diffs pre-sorted -> first is min
                break
        if blocker is not None:
            t4_results[s["verdict_id"]] = ("blocked", blocker)
        else:
            dsu.union(ra, rb)
            t4_results[s["verdict_id"]] = ("merged", None)
    for d in diff_rows:
        t4_results[d["verdict_id"]] = ("constraint", None)

    groups = {}
    for member in region:
        groups.setdefault(dsu.find(member), []).append(member)
    new_map = {}
    for members in groups.values():
        canon = min(members)  # byte-minimum member, never a tree root
        for m in members:
            new_map[m] = canon
    return new_map, t4_results, same_rows, diff_rows


# --------------------------------------------------------------------- diffing ----

def _diff_table(old_rows, new_rows, columns, table_name, revision, parent):
    """Emit change records from strict before/after row differences."""
    changes = []
    keys = sorted(set(old_rows) | set(new_rows))
    for key in keys:
        if key not in old_rows:
            changes.append((table_name, key, "replace",
                            json.dumps(dict(zip(columns, new_rows[key])),
                                       ensure_ascii=False)))
        elif key not in new_rows:
            changes.append((table_name, key, "delete", None))
        elif old_rows[key] != new_rows[key]:
            changes.append((table_name, key, "replace",
                            json.dumps(dict(zip(columns, new_rows[key])),
                                       ensure_ascii=False)))
    return changes


# -------------------------------------------------------------------- apply batch

def apply_batch(master_path: str, batch_bytes: bytes) -> dict:
    doc = _load_batch(batch_bytes)
    digest = hashlib.sha256(batch_bytes).hexdigest()
    conn = connect(master_path)
    conn.set_phase("batch")
    conn.reset_acct()
    try:
        conn.execute("BEGIN IMMEDIATE")  # writers serialize; at most one wins

        # 1) idempotency / batch-id conflict takes precedence over parent age,
        #    so an identical resend is never refused after the head advanced.
        receipt = conn.execute(
            "SELECT * FROM batch_receipts WHERE batch_id=?",
            (doc["batch_id"],)).fetchone()
        if receipt is not None:
            if receipt["input_digest"] == digest and \
                    receipt["input_size"] == len(batch_bytes):
                conn.commit()
                return _receipt_dict(receipt, deduplicated=True,
                                     access=conn.access_snapshot())
            conn.rollback()
            raise SGError("batch-id-conflict",
                          "a different batch with the same batch id was already applied")

        # 2) expected parent must be the current head.
        head = conn.execute("SELECT MAX(revision) AS r FROM revisions").fetchone()["r"]
        if head != doc["expected_parent"]:
            conn.rollback()
            raise SGError("stale-parent-revision",
                          "the batch's expected parent revision is not current")

        # 3) whole-batch validation against current state (all-or-nothing).
        effective, _touched, current = _validate_and_stage(conn, doc)

        # A batch with no operations has no region and no row effects; it still
        # publishes a revision header so its batch id becomes a valid receipt.
        if not doc["operations"]:
            conn.execute(
                "INSERT INTO revisions(revision, parent_revision, batch_id,"
                " created_at, change_count, note) VALUES(?,?,?,?,?,?)",
                (head + 1, head, doc["batch_id"], _now(), 0, "batch"))
            conn.execute(
                "INSERT INTO batch_receipts(batch_id, input_digest, input_size,"
                " expected_parent, received_revision, published_revision,"
                " applied_at, operation_count, change_count)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (doc["batch_id"], digest, len(batch_bytes), doc["expected_parent"],
                 head, head + 1, _now(), 0, 0))
            if os.environ.get(FAULT_ENV) == "1":
                raise RuntimeError("injected fault before commit")
            conn.commit()
            receipt = conn.execute(
                "SELECT * FROM batch_receipts WHERE batch_id=?",
                (doc["batch_id"],)).fetchone()
            return _receipt_dict(receipt, deduplicated=False,
                                 access=conn.access_snapshot())

        # 4) collect region seeds from both the replaced and the new rows.
        seeds = set()
        for vid, new_row in effective.items():
            old = current.get(vid)
            if old is not None:
                seeds.add(old["endpoint_a"])
                seeds.add(old["endpoint_b"])
            if new_row is not None:
                seeds.add(new_row["endpoint_a"])
                seeds.add(new_row["endpoint_b"])

        # 5) persist the post-batch ledger up front so region BFS/recompute see
        #    the new effective set through normal indexed SQL.
        for vid, new_row in effective.items():
            if new_row is None:
                conn.execute(
                    "UPDATE adjudications SET status='retracted',"
                    " updated_in_batch=?, updated_revision=? WHERE verdict_id=?",
                    (doc["batch_id"], head + 1, vid))
            else:
                conn.execute(
                    "INSERT INTO adjudications(verdict_id, kind, endpoint_a, endpoint_b,"
                    " priority, status, updated_in_batch, updated_revision)"
                    " VALUES(?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(verdict_id) DO UPDATE SET kind=excluded.kind,"
                    " endpoint_a=excluded.endpoint_a, endpoint_b=excluded.endpoint_b,"
                    " priority=excluded.priority, status='active',"
                    " updated_in_batch=excluded.updated_in_batch,"
                    " updated_revision=excluded.updated_revision",
                    (vid, new_row["kind"], new_row["endpoint_a"], new_row["endpoint_b"],
                     new_row["priority"], "active", doc["batch_id"], head + 1))

        # 6) closed region recompute (same-reachability incl. blocked ones).
        region = _same_adjacency(conn, seeds)
        # Endpoints only touched by a `different` verdict are still in region.
        for node in seeds:
            region.add(node)
        new_map, t4_results, same_rows, diff_rows = _recompute_region(
            conn, region, effective)

        all_changes = []

        # ---- T1: entity map (only region rows can change) ----
        rl = sorted(region)
        old_t1 = {}
        for r in conn.execute(
                "SELECT obj_id, obj_type, canonical_id FROM t1_entity_map"
                f" WHERE obj_id IN ({_placeholders(rl)})", rl).fetchall():
            old_t1[r["obj_id"]] = tuple(r[c] for c in T1_COLS)
        type_lookup = {r["obj_id"]: r["obj_type"] for r in conn.execute(
            "SELECT obj_id, obj_type FROM base_objects"
            f" WHERE obj_id IN ({_placeholders(rl)})", rl).fetchall()}
        new_t1 = {m: (m, type_lookup[m], new_map[m]) for m in rl}
        all_changes += _diff_table(old_t1, new_t1, T1_COLS, T_ENTITY,
                                   head + 1, head)
        conn.executemany(
            "INSERT INTO t1_entity_map(obj_id, obj_type, canonical_id)"
            " VALUES(?,?,?) ON CONFLICT(obj_id) DO UPDATE SET"
            " obj_type=excluded.obj_type, canonical_id=excluded.canonical_id",
            list(new_t1.values()))

        # ---- T4: active verdicts with results / blocking evidence ----
        # Universe = every active verdict touching the region (indexed lookup),
        # plus any verdict retracted in this batch.  No full ledger scan.
        universe = set(t4_results)
        for r in conn.execute(
                "SELECT verdict_id FROM adjudications WHERE status='active' AND ("
                f"endpoint_a IN ({_placeholders(rl)})"
                f" OR endpoint_b IN ({_placeholders(rl)}))",
                rl + rl).fetchall():
            universe.add(r["verdict_id"])
        for vid, new_row in effective.items():
            if new_row is None:
                universe.add(vid)
        old_t4 = {}
        new_t4 = {}
        if universe:
            ul = sorted(universe)
            for r in conn.execute(
                    "SELECT verdict_id, kind, endpoint_a, endpoint_b, priority,"
                    " result, blocking_verdict_id FROM t4_verdicts"
                    f" WHERE verdict_id IN ({_placeholders(ul)})", ul).fetchall():
                old_t4[r["verdict_id"]] = tuple(r[c] for c in T4_COLS)
            for r in conn.execute(
                    "SELECT * FROM adjudications WHERE status='active' AND"
                    f" verdict_id IN ({_placeholders(ul)})", ul).fetchall():
                vid = r["verdict_id"]
                result, blocker = t4_results[vid]
                new_t4[vid] = (vid, r["kind"], r["endpoint_a"], r["endpoint_b"],
                               r["priority"], result, blocker)
        # retracted universe members stay absent from new_t4 -> delete changes.
        all_changes += _diff_table(old_t4, new_t4, T4_COLS, T_VERDICT,
                                   head + 1, head)
        if universe:
            conn.execute(f"DELETE FROM t4_verdicts WHERE verdict_id IN "
                         f"({_placeholders(sorted(universe))})", sorted(universe))
            conn.executemany(
                "INSERT INTO t4_verdicts(verdict_id, kind, endpoint_a, endpoint_b,"
                " priority, result, blocking_verdict_id) VALUES(?,?,?,?,?,?,?)",
                list(new_t4.values()))

        # ---- relations: only edges touching the region ----
        affected = [r["relationship_id"] for r in conn.execute(
            "SELECT relationship_id FROM base_edges"
            f" WHERE source_id IN ({_placeholders(rl)})"
            f" OR target_id IN ({_placeholders(rl)})",
            rl + rl).fetchall()]
        old_t3 = {}
        if affected:
            for r in conn.execute(
                    "SELECT * FROM t3_contributions"
                    f" WHERE relationship_id IN ({_placeholders(affected)})",
                    affected).fetchall():
                old_t3[r["relationship_id"]] = tuple(r[c] for c in T3_COLS)

        outside_canon = {}

        def canon_of(x):
            if x in new_map:
                return new_map[x]
            if x not in outside_canon:
                row = conn.execute(
                    "SELECT canonical_id FROM t1_entity_map WHERE obj_id=?",
                    (x,)).fetchone()
                outside_canon[x] = row["canonical_id"]
            return outside_canon[x]

        new_t3 = {}
        agg = {}
        if affected:
            edge_rows = conn.execute(
                "SELECT * FROM base_edges"
                f" WHERE relationship_id IN ({_placeholders(affected)})",
                affected).fetchall()
            for e in edge_rows:
                sc, tc = canon_of(e["source_id"]), canon_of(e["target_id"])
                rk = _row_key(sc, e["relationship_type"], tc)
                sl = 1 if sc == tc else 0
                new_t3[e["relationship_id"]] = (
                    e["relationship_id"], e["source_id"], e["target_id"],
                    e["relationship_type"], sc, tc, rk, sl,
                    e["modified_key"], e["modified_raw"])
                agg.setdefault(rk, []).append(
                    (sc, e["relationship_type"], tc, sl))
        all_changes += _diff_table(old_t3, new_t3, T3_COLS, T_CONTRIB,
                                   head + 1, head)
        if affected:
            conn.execute(
                f"DELETE FROM t3_contributions WHERE relationship_id IN "
                f"({_placeholders(affected)})", affected)
            conn.executemany(
                "INSERT INTO t3_contributions(relationship_id, source_id, target_id,"
                " relationship_type, source_canon, target_canon, row_key,"
                " is_self_loop, modified_key, modified_raw)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)", list(new_t3.values()))

        touched_keys = set()
        for tup in old_t3.values():
            touched_keys.add(tup[T3_COLS.index("row_key")])
        touched_keys.update(agg.keys())
        old_t2 = {}
        if touched_keys:
            kl = sorted(touched_keys)
            for r in conn.execute(
                    "SELECT * FROM t2_relations"
                    f" WHERE row_key IN ({_placeholders(kl)})", kl).fetchall():
                old_t2[r["row_key"]] = tuple(r[c] for c in T2_COLS)
        new_t2 = {}
        for rk, members in agg.items():
            sc, rel, tc, sl = members[0]
            new_t2[rk] = (rk, sc, rel, tc, len(members), sl)
        all_changes += _diff_table(old_t2, new_t2, T2_COLS, T_REL,
                                   head + 1, head)
        if touched_keys:
            conn.execute(
                f"DELETE FROM t2_relations WHERE row_key IN "
                f"({_placeholders(sorted(touched_keys))})",
                sorted(touched_keys))
            conn.executemany(
                "INSERT INTO t2_relations(row_key, source_canon, relationship_type,"
                " target_canon, contribution_count, is_self_loop)"
                " VALUES(?,?,?,?,?,?)", list(new_t2.values()))

        # 7) deterministic ordering: table group then row key.
        order = {t: i for i, t in enumerate(TABLE_ORDER)}
        all_changes.sort(key=lambda c: (order[c[0]], c[1]))
        for table_name, row_key, op, row_json in all_changes:
            conn.execute(
                "INSERT INTO changes(revision, parent_revision, table_name, row_key,"
                " op, row_json) VALUES(?,?,?,?,?,?)",
                (head + 1, head, table_name, row_key, op, row_json))

        conn.execute(
            "INSERT INTO revisions(revision, parent_revision, batch_id, created_at,"
            " change_count, note) VALUES(?,?,?,?,?,?)",
            (head + 1, head, doc["batch_id"], _now(), len(all_changes), "batch"))
        conn.execute(
            "INSERT INTO batch_receipts(batch_id, input_digest, input_size,"
            " expected_parent, received_revision, published_revision, applied_at,"
            " operation_count, change_count)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (doc["batch_id"], digest, len(batch_bytes), doc["expected_parent"],
             head, head + 1, _now(), len(doc["operations"]), len(all_changes)))

        if os.environ.get(FAULT_ENV) == "1":
            raise RuntimeError("injected fault before commit")
        conn.commit()
        receipt = conn.execute(
            "SELECT * FROM batch_receipts WHERE batch_id=?",
            (doc["batch_id"],)).fetchone()
        return _receipt_dict(receipt, deduplicated=False,
                             access=conn.access_snapshot())
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _receipt_dict(row, deduplicated, access):
    return {
        "batch_id": row["batch_id"],
        "published_revision": row["published_revision"],
        "parent_revision": row["received_revision"],
        "expected_parent": row["expected_parent"],
        "change_count": row["change_count"],
        "operation_count": row["operation_count"],
        "input_digest_sha256": row["input_digest"],
        "deduplicated": deduplicated,
        "status": "sealed",
        "access": access,
    }


# ----------------------------------------------------------------------- reads

def read_all(master_path: str) -> dict:
    """One consistent snapshot read of all four logical tables + revision."""
    conn = connect(master_path)
    conn.set_phase("read")
    try:
        conn.execute("BEGIN")
        head = conn.execute("SELECT MAX(revision) AS r FROM revisions").fetchone()["r"]
        out = {"revision": head, "tables": {}}
        out["tables"][T_ENTITY] = [
            dict(zip(T1_COLS, r)) for r in conn.execute(
                "SELECT obj_id, obj_type, canonical_id FROM t1_entity_map"
                " ORDER BY obj_id")]
        out["tables"][T_REL] = [
            dict(zip(T2_COLS, r)) for r in conn.execute(
                "SELECT row_key, source_canon, relationship_type, target_canon,"
                " contribution_count, is_self_loop FROM t2_relations"
                " ORDER BY row_key")]
        out["tables"][T_CONTRIB] = [
            dict(zip(T3_COLS, r)) for r in conn.execute(
                "SELECT relationship_id, source_id, target_id, relationship_type,"
                " source_canon, target_canon, row_key, is_self_loop, modified_key,"
                " modified_raw FROM t3_contributions ORDER BY relationship_id")]
        out["tables"][T_VERDICT] = [
            dict(zip(T4_COLS, r)) for r in conn.execute(
                "SELECT verdict_id, kind, endpoint_a, endpoint_b, priority,"
                " result, blocking_verdict_id FROM t4_verdicts"
                " ORDER BY verdict_id")]
        conn.execute("ROLLBACK")
        return out
    finally:
        conn.close()


def read_changes(master_path: str, from_revision: int, to_revision: int):
    """Yield deterministic JSONL-ready dicts for revisions in [from, to]."""
    conn = connect(master_path)
    conn.set_phase("read")
    try:
        revs = conn.execute(
            "SELECT * FROM revisions WHERE revision BETWEEN ? AND ?"
            " ORDER BY revision", (from_revision, to_revision)).fetchall()
        if not revs:
            raise SGError("unknown-revision", "no committed revision in that range")
        for rev in revs:
            yield {"type": "revision_header", "revision": rev["revision"],
                   "parent_revision": rev["parent_revision"],
                   "batch_id": rev["batch_id"], "change_count": rev["change_count"],
                   "note": rev["note"]}
            order = {t: i for i, t in enumerate(TABLE_ORDER)}
            rows = conn.execute(
                "SELECT * FROM changes WHERE revision=?"
                " ORDER BY table_name, row_key, change_seq",
                (rev["revision"],)).fetchall()
            # ORDER BY table_name needs the fixed logical ordering, not alpha.
            rows = sorted(rows, key=lambda r: (order[r["table_name"]], r["row_key"]))
            for r in rows:
                yield {"type": "change", "revision": r["revision"],
                       "parent_revision": r["parent_revision"],
                       "table": r["table_name"], "row_key": r["row_key"],
                       "op": r["op"],
                       "row": json.loads(r["row_json"]) if r["row_json"] else None}
    finally:
        conn.close()


def list_revisions(master_path: str) -> list:
    conn = connect(master_path)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT revision, parent_revision, batch_id, created_at, change_count, note"
            " FROM revisions ORDER BY revision")]
    finally:
        conn.close()


def package_context(master_path: str) -> dict:
    conn = connect(master_path)
    try:
        return {r["key"]: r["value"] for r in
                conn.execute("SELECT key, value FROM package_meta ORDER BY key")}
    finally:
        conn.close()
