"""Master-data release packages: quality-contract gating of the current head.

A data steward supplies one JSON quality contract and gets a self-contained
SQLite package built from one *committed* view (the head revision, read inside
a single read transaction) of an existing master warehouse.  The package has a
load side with exactly the rows that passed and a reject ledger explaining
every input row that did not, wave by wave.  Nothing here changes a verdict or
creates a master revision, and it is not a revision-to-revision diff.

Gating semantics.  Wave 0 removes the master entities the contract explicitly
excludes together with every relationship touching them, and drops every
relationship whose type the contract does not allow.  Wave 1 and later judge
the *same* surviving frontier: all entities failing at the frontier are evicted
together, and only the next wave may count that eviction against someone
else's support.  A relationship leaves with its first evicted endpoint.  The
loop stops when a wave evicts nobody; everything left is loaded.  Support rules
read direction from the merged relation view and count distinct *peer master
entities*, de-duplicated by peer id, so several relationship types — or several
source contributions — between one pair of endpoints still count once.
Self-loops provide no support but are released when their type is allowed and
their endpoint survives.  Cycles that genuinely support one another therefore
stay, with no human-chosen root.

For every automatically evicted entity the ledger stores the first eviction
wave, every requirement group unmet at that wave, and each alternative's
measured distinct-peer count at that frontier together with its threshold.
Those numbers are captured when the wave is decided, never back-filled from a
later (possibly empty) graph.

Guarantees:

* an unknown rule/group/set id, an empty alternative list, an unknown excluded
  master entity, an unknown direction, a non-positive or non-integer minimum,
  a duplicate id and any malformed field are configuration errors
  (``invalid-contract``) — never a silently empty delivery.  Relationship
  types declared but absent from this warehouse are legal;
* every input row (entity map, relation, contribution) lands on exactly one
  side, every loaded relation has both endpoints loaded, and every loaded
  contribution is traceable;
* the wave ledger names concrete rows, not only aggregate counts;
* the package records the upstream projection identity, the master revision
  read and the contract digest, and copies no verdict table;
* the same head view and contract produce identical logical tables and
  reasons, publication is atomic, and a failed run leaves neither a loadable
  new package nor damage to an existing package at the target path;
* support facts and per-wave access counts are persisted in the package, so a
  release can be re-run and its access volume compared.

Input is exactly the committed head view of three logical tables
(``entity_map``, ``relations``, ``contributions``) plus the warehouse's sealed
projection metadata; the verdict table is never read and the raw source
repository is never opened.  The merged relation view already keeps the
relationship type on every row, which is what per-type allowance and per-peer
de-duplication need.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone

from .util import SGError, canon

CONTRACT_SCHEMA = "stix-gate-master-release-contract/1"
PACKAGE_SCHEMA = "stix-gate-master-release/1"


# ------------------------------------------------------------- instrumentation ----

_TRACKED_TABLES = (
    "package_meta", "in_entity_map", "in_relations", "in_contributions",
    "contract_allowed_relationships",
    "contract_excluded_entities", "contract_requirement_sets",
    "contract_set_groups", "contract_groups", "contract_alternatives",
    "contract_alternative_relationship_types",
    "contract_alternative_peer_types", "release_entity_state",
    "release_relation_state", "load_entities", "load_relations",
    "load_contributions", "reject_entity_map", "reject_relations",
    "reject_contributions", "release_waves", "wave_entity_evictions",
    "eviction_alt_snapshot", "support", "support_count", "release_frontier",
    "release_access",
)
_SELECT_RE = re.compile(r"^\s*(SELECT|WITH)\b", re.I)
_DML_RE = re.compile(r"^\s*(INSERT|REPLACE|UPDATE|DELETE)\b", re.I)
_WHERE_RE = re.compile(r"\bWHERE\b", re.I)
_TABLE_RE = re.compile(r"\b(" + "|".join(_TRACKED_TABLES) + r")\b")


class BuildConnection(sqlite3.Connection):
    """Connection counting filtered reads, full scans and writes per phase."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.row_factory = sqlite3.Row
        self.acct = {}
        self._phase = "setup"

    def set_phase(self, phase: str):
        self._phase = phase

    def reset_acct(self):
        self.acct = {}

    def access_snapshot(self) -> dict:
        return json.loads(json.dumps(self.acct))

    def _record(self, sql: str):
        if _SELECT_RE.match(sql):
            kind = "filtered" if _WHERE_RE.search(sql) else "scan"
        elif _DML_RE.match(sql):
            kind = "write"
        else:
            return
        for table in sorted(set(_TABLE_RE.findall(sql))):
            self.acct.setdefault(self._phase, {}).setdefault(
                table, {"filtered": 0, "scan": 0, "write": 0})[kind] += 1

    def execute(self, sql, parameters=()):
        self._record(sql)
        return super().execute(sql, parameters)

    def executemany(self, sql, parameters):
        self._record(sql)
        return super().executemany(sql, parameters)


# ------------------------------------------------------------------ schema ----

SCHEMA = """
CREATE TABLE package_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- sealed input projection copied from the master warehouse (analysis only)
CREATE TABLE in_entity_map (
    obj_id       TEXT,
    obj_type     TEXT,
    canonical_id TEXT
);
CREATE INDEX ix_in_map_obj ON in_entity_map(obj_id);
CREATE INDEX ix_in_map_canon ON in_entity_map(canonical_id);
CREATE INDEX ix_in_map_type ON in_entity_map(obj_type, canonical_id);

CREATE TABLE in_relations (
    row_key            TEXT,
    source_canon       TEXT,
    relationship_type  TEXT,
    target_canon       TEXT,
    contribution_count INTEGER,
    is_self_loop       INTEGER
);
CREATE INDEX ix_in_rel_src ON in_relations(source_canon);
CREATE INDEX ix_in_rel_tgt ON in_relations(target_canon);

CREATE TABLE in_contributions (
    relationship_id   TEXT,
    source_id         TEXT,
    target_id         TEXT,
    relationship_type TEXT,
    source_canon      TEXT,
    target_canon      TEXT,
    row_key           TEXT,
    is_self_loop      INTEGER,
    modified_key      INTEGER,
    modified_raw      TEXT
);
CREATE INDEX ix_in_contrib_row ON in_contributions(row_key);

-- normalized contract (stable ids echoed for audit)
CREATE TABLE contract_allowed_relationships (
    relationship_type TEXT PRIMARY KEY
);
CREATE TABLE contract_excluded_entities (
    entity_id TEXT PRIMARY KEY
);
CREATE TABLE contract_groups (
    group_id TEXT PRIMARY KEY
);
CREATE TABLE contract_alternatives (
    alt_id     TEXT PRIMARY KEY,
    group_id   TEXT NOT NULL,
    direction  TEXT NOT NULL,
    min_peers  INTEGER NOT NULL
);
CREATE TABLE contract_alternative_relationship_types (
    alt_id            TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    PRIMARY KEY (alt_id, relationship_type)
);
CREATE TABLE contract_alternative_peer_types (
    alt_id    TEXT NOT NULL,
    peer_type TEXT NOT NULL,
    PRIMARY KEY (alt_id, peer_type)
);
CREATE TABLE contract_requirement_sets (
    set_id      TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL UNIQUE
);
CREATE TABLE contract_set_groups (
    set_id   TEXT NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (set_id, group_id)
);

-- final state of every input entity / relation row (one row each, no gaps)
CREATE TABLE release_entity_state (
    entity_id       TEXT PRIMARY KEY,
    entity_type     TEXT NOT NULL,
    status          TEXT NOT NULL,      -- live | loaded | rejected
    eviction_wave   INTEGER,
    reason          TEXT
);
CREATE INDEX ix_res_wave ON release_entity_state(eviction_wave);

-- Entities whose support may have shifted in the previous wave (delta
-- frontier for the next judgement).  Rebuilt per wave, never a warehouse scan.
CREATE TABLE release_frontier (
    entity_id TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE release_relation_state (
    row_key                 TEXT PRIMARY KEY,
    source_canon            TEXT NOT NULL,
    relationship_type       TEXT NOT NULL,
    target_canon            TEXT NOT NULL,
    contribution_count      INTEGER NOT NULL,
    is_self_loop            INTEGER NOT NULL,
    status                  TEXT NOT NULL,   -- live | loaded | rejected
    eviction_wave           INTEGER,
    reason                  TEXT
);
CREATE INDEX ix_rrs_src ON release_relation_state(source_canon);
CREATE INDEX ix_rrs_tgt ON release_relation_state(target_canon);
CREATE INDEX ix_rrs_wave ON release_relation_state(eviction_wave);

-- load side (no verdict table anywhere)
CREATE TABLE load_entities (
    obj_id       TEXT PRIMARY KEY,
    obj_type     TEXT NOT NULL,
    canonical_id TEXT NOT NULL
);
CREATE TABLE load_relations (
    row_key            TEXT PRIMARY KEY,
    source_canon       TEXT NOT NULL,
    relationship_type  TEXT NOT NULL,
    target_canon       TEXT NOT NULL,
    contribution_count INTEGER NOT NULL,
    is_self_loop       INTEGER NOT NULL
);
CREATE TABLE load_contributions (
    relationship_id   TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    source_canon      TEXT NOT NULL,
    target_canon      TEXT NOT NULL,
    row_key           TEXT NOT NULL,
    is_self_loop      INTEGER NOT NULL,
    modified_key      INTEGER NOT NULL,
    modified_raw      TEXT NOT NULL
);
CREATE INDEX ix_load_contrib_row ON load_contributions(row_key);

-- reject side: original keys plus where / why the row stopped
CREATE TABLE reject_entity_map (
    obj_id           TEXT PRIMARY KEY,
    obj_type         TEXT NOT NULL,
    canonical_id     TEXT NOT NULL,
    master_entity_id TEXT NOT NULL,
    eviction_wave    INTEGER NOT NULL,
    reason           TEXT NOT NULL
);
CREATE TABLE reject_relations (
    row_key                TEXT PRIMARY KEY,
    source_canon           TEXT NOT NULL,
    relationship_type      TEXT NOT NULL,
    target_canon           TEXT NOT NULL,
    contribution_count     INTEGER NOT NULL,
    is_self_loop           INTEGER NOT NULL,
    eviction_wave          INTEGER NOT NULL,
    reason                 TEXT NOT NULL,
    evicted_endpoints_json TEXT NOT NULL
);
CREATE TABLE reject_contributions (
    relationship_id   TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    source_canon      TEXT NOT NULL,
    target_canon      TEXT NOT NULL,
    row_key           TEXT NOT NULL,
    is_self_loop      INTEGER NOT NULL,
    modified_key      INTEGER NOT NULL,
    modified_raw      TEXT NOT NULL,
    eviction_wave     INTEGER NOT NULL,
    reason            TEXT NOT NULL
);

-- per-wave accounting (access_json is re-runnable access evidence)
CREATE TABLE release_waves (
    wave                   INTEGER PRIMARY KEY,
    phase                  TEXT NOT NULL,
    evicted_entities       INTEGER NOT NULL,
    evicted_relations      INTEGER NOT NULL,
    evicted_mappings       INTEGER NOT NULL,
    evicted_contributions  INTEGER NOT NULL,
    candidate_entities     INTEGER NOT NULL,
    probed_counter_rows    INTEGER NOT NULL,
    lost_support_pairs     INTEGER NOT NULL,
    access_json            TEXT NOT NULL
);
CREATE TABLE wave_entity_evictions (
    entity_id     TEXT PRIMARY KEY,
    wave          INTEGER NOT NULL,
    entity_type   TEXT NOT NULL,
    reason        TEXT NOT NULL
);
CREATE INDEX ix_wee_wave ON wave_entity_evictions(wave);
CREATE TABLE eviction_alt_snapshot (
    entity_id      TEXT NOT NULL,
    wave           INTEGER NOT NULL,
    group_id       TEXT NOT NULL,
    alt_id         TEXT NOT NULL,
    direction      TEXT NOT NULL,
    distinct_peers INTEGER NOT NULL,
    min_peers      INTEGER NOT NULL,
    met            INTEGER NOT NULL,
    PRIMARY KEY (entity_id, wave, group_id, alt_id)
);

-- support facts: one row per (alternative, entity, distinct peer)
CREATE TABLE support (
    alt_id    TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    peer_id   TEXT NOT NULL,
    PRIMARY KEY (entity_id, alt_id, peer_id)
) WITHOUT ROWID;
CREATE INDEX ix_support_peer ON support(peer_id);

-- running distinct-peer counts, one row per (entity, alternative).  Kept in
-- step with ``support`` by exact decrements for the peers a wave removes, so
-- no wave ever re-groups or re-walks a neighbourhood.
CREATE TABLE support_count (
    entity_id TEXT NOT NULL,
    alt_id    TEXT NOT NULL,
    c         INTEGER NOT NULL,
    PRIMARY KEY (entity_id, alt_id)
) WITHOUT ROWID;


-- reproducible access evidence, one row per phase/table/kind
CREATE TABLE release_access (
    phase      TEXT NOT NULL,
    table_name TEXT NOT NULL,
    kind       TEXT NOT NULL,
    count      INTEGER NOT NULL
);
CREATE INDEX ix_access_phase ON release_access(phase);
"""


# ------------------------------------------------------------------ contract ----

def _bad_contract(code="invalid-contract"):
    return SGError(code, "the release contract is not valid")


def _strict_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def load_contract(doc) -> dict:
    """Validate and normalize a contract; every id must be stable and sound."""
    if not isinstance(doc, dict):
        raise _bad_contract()
    if doc.get("schema") != CONTRACT_SCHEMA:
        raise _bad_contract()

    rel_types = doc.get("relationship_types")
    if not isinstance(rel_types, list) or not rel_types or not all(
            isinstance(t, str) and t for t in rel_types):
        raise _bad_contract()
    if len(set(rel_types)) != len(rel_types):
        raise _bad_contract()

    excluded = doc.get("exclude_entity_ids")
    if not isinstance(excluded, list) or not all(
            isinstance(e, str) and e for e in excluded):
        raise _bad_contract()
    if len(set(excluded)) != len(excluded):
        raise _bad_contract()

    raw_groups = doc.get("requirement_groups")
    if not isinstance(raw_groups, list):
        raise _bad_contract()
    groups = {}
    for grp in raw_groups:
        if not isinstance(grp, dict):
            raise _bad_contract()
        gid = grp.get("id")
        if not isinstance(gid, str) or not gid or gid in groups:
            raise _bad_contract()
        alts = grp.get("alternatives")
        if not isinstance(alts, list) or not alts:
            raise _bad_contract()  # declared but empty is never a quiet drop
        parsed = []
        seen = set()
        for alt in alts:
            if not isinstance(alt, dict):
                raise _bad_contract()
            aid = alt.get("id")
            direction = alt.get("direction")
            rts = alt.get("relationship_types")
            pts = alt.get("peer_types")
            minimum = alt.get("min_distinct_peers")
            if not isinstance(aid, str) or not aid or aid in seen:
                raise _bad_contract()
            seen.add(aid)
            if direction not in ("in", "out"):
                raise _bad_contract()
            if not isinstance(rts, list) or not rts or not all(
                    isinstance(t, str) and t for t in rts):
                raise _bad_contract()
            if len(set(rts)) != len(rts):
                raise _bad_contract()
            if not isinstance(pts, list) or not pts or not all(
                    isinstance(t, str) and t for t in pts):
                raise _bad_contract()
            if len(set(pts)) != len(pts):
                raise _bad_contract()
            if not _strict_int(minimum) or minimum < 1:
                raise _bad_contract()
            parsed.append({"id": aid, "direction": direction,
                           "relationship_types": list(rts),
                           "peer_types": list(pts),
                           "min_distinct_peers": minimum})
        groups[gid] = {"id": gid, "alternatives": parsed}

    raw_sets = doc.get("named_requirement_sets")
    if not isinstance(raw_sets, list):
        raise _bad_contract()
    sets = {}
    for entry in raw_sets:
        if not isinstance(entry, dict):
            raise _bad_contract()
        sid = entry.get("id")
        ent_type = entry.get("entity_type")
        refs = entry.get("groups")
        if not isinstance(sid, str) or not sid or not isinstance(ent_type, str) \
                or not ent_type:
            raise _bad_contract()
        if ent_type in sets:
            raise _bad_contract()  # one named set per entity type
        if not isinstance(refs, list) or not refs \
                or not all(isinstance(g, str) and g for g in refs):
            raise _bad_contract()
        if len(set(refs)) != len(refs):
            raise _bad_contract()
        for gid in refs:
            if gid not in groups:
                raise _bad_contract()  # unknown group reference
        sets[ent_type] = {"id": sid, "entity_type": ent_type,
                          "groups": list(refs)}

    normalized = {
        "schema": CONTRACT_SCHEMA,
        "relationship_types": list(rel_types),
        "exclude_entity_ids": list(excluded),
        "requirement_groups": [groups[g] for g in sorted(groups)],
        "named_requirement_sets": [sets[t] for t in sorted(sets)],
    }
    normalized["sha256"] = hashlib.sha256(canon(normalized)).hexdigest()
    return normalized


def load_contract_bytes(raw: bytes) -> dict:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _bad_contract("invalid-contract-json")
    return load_contract(doc)


# ------------------------------------------------------------------- helpers ----

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _marks(values) -> str:
    return ",".join("?" for _ in values)


def _copy_rows(src, dst, select_sql, insert_sql, chunk=2000):
    cur = src.execute(select_sql)
    total = 0
    while True:
        batch = cur.fetchmany(chunk)
        if not batch:
            break
        dst.executemany(insert_sql, [tuple(r) for r in batch])
        total += len(batch)
    return total


def _scalar(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()[0]


# -------------------------------------------------------------------- build ----

_META_UPSTREAM_KEYS = (
    "codename", "t_raw", "t_key", "principal", "policy_digest", "signing_key",
    "schema", "package_digest_sha256", "package_size_bytes",
    "warehouse_instance_id", "warehouse_schema", "built_at",
    "base_entity_count", "base_edge_count", "rejected_edge_count",
)


def build_package(master_path: str, contract: dict, output_path: str) -> dict:
    """Run one release and atomically publish the package."""
    if not os.path.exists(master_path):
        raise SGError("master-missing",
                      "no master warehouse at that path; run master-build first")
    out_dir = os.path.dirname(os.path.abspath(output_path)) or "."
    if not os.path.isdir(out_dir):
        raise SGError("file-not-found", "the output directory does not exist")
    fd, tmp_path = tempfile.mkstemp(suffix=".sqlite.tmp",
                                    prefix=os.path.basename(output_path) + ".",
                                    dir=out_dir)
    os.close(fd)
    src = None
    conn = None
    try:
        src = sqlite3.connect(f"file:{os.path.abspath(master_path)}?mode=ro",
                              uri=True)
        src.row_factory = sqlite3.Row
        src.execute("BEGIN")  # one committed view for every read below
        upstream_meta = {r["key"]: r["value"] for r in src.execute(
            "SELECT key, value FROM package_meta")}
        revision = src.execute(
            "SELECT MAX(revision) AS r FROM revisions").fetchone()["r"]
        if revision is None:
            raise SGError("master-missing", "warehouse has no committed revision")

        conn = sqlite3.connect(tmp_path, factory=BuildConnection)
        conn.isolation_level = None
        conn.executescript(SCHEMA)
        conn.execute("BEGIN")

        # ---- input: seal the head view into the package database ----
        conn.set_phase("input")
        _copy_rows(
            src, conn,
            "SELECT obj_id, obj_type, canonical_id FROM t1_entity_map"
            " ORDER BY obj_id",
            "INSERT INTO in_entity_map VALUES(?,?,?)")
        _copy_rows(
            src, conn,
            "SELECT row_key, source_canon, relationship_type, target_canon,"
            " contribution_count, is_self_loop FROM t2_relations ORDER BY row_key",
            "INSERT INTO in_relations VALUES(?,?,?,?,?,?)")
        _copy_rows(
            src, conn,
            "SELECT relationship_id, source_id, target_id, relationship_type,"
            " source_canon, target_canon, row_key, is_self_loop, modified_key,"
            " modified_raw FROM t3_contributions ORDER BY relationship_id",
            "INSERT INTO in_contributions VALUES(?,?,?,?,?,?,?,?,?,?)")
        src.execute("ROLLBACK")  # snapshot complete; never mixes writers
        src.close()
        src = None

        _validate_against_input(conn, contract)
        _write_contract(conn, contract)
        _write_meta(conn, master_path, revision, upstream_meta, contract)

        # ---- wave 0: explicit exclusions + disallowed relationship types ----
        conn.set_phase("wave-0")
        _init_entity_state(conn)
        _init_relation_state(conn)
        _build_support(conn)
        _record_wave(conn, 0, "contract-wave",
                     candidates=_scalar(conn, "SELECT COUNT(*) FROM release_entity_state"),
                     probed=_scalar(conn, "SELECT COUNT(*) FROM support"),
                     lost=0)

        # ---- eliminate until no wave evicts anybody, then publish ----
        wave = 1
        while True:
            conn.set_phase(f"wave-{wave}")
            evicted, candidates, probed, lost = _run_wave(conn, wave)
            _record_wave(conn, wave,
                         "elimination-wave" if evicted else "stabilized",
                         candidates=candidates, probed=probed, lost=lost)
            if not evicted:
                break
            wave += 1
        wave_count = wave - 1
        conn.execute("UPDATE release_entity_state SET status='loaded'"
                     " WHERE status='live'")
        conn.execute("UPDATE release_relation_state SET status='loaded'"
                     " WHERE status='live'")

        # ---- derive load / reject surfaces + endpoint evidence ----
        conn.set_phase("ledger")
        _finalize_surfaces(conn)
        _verify_partition(conn)
        digest = _release_digest(conn)
        _record_access(conn)
        conn.execute("INSERT INTO package_meta(key, value) VALUES(?,?)",
                     ("release_digest", digest))
        conn.execute("INSERT INTO package_meta(key, value) VALUES(?,?)",
                     ("wave_count", str(wave_count)))
        conn.execute("INSERT INTO package_meta(key, value) VALUES(?,?)",
                     ("published_at", _now()))
        conn.execute("COMMIT")

        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise SGError("integrity-failure",
                          "release package fails integrity check")
        conn.close()
        conn = None
        os.replace(tmp_path, output_path)  # atomic publish
    except Exception:
        if src is not None:
            try:
                src.rollback()
            except sqlite3.Error:
                pass
            src.close()
        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            conn.close()
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return receipt(output_path)


# --------------------------------------------------- validate contract vs input ----

def _validate_against_input(conn, contract):
    """Reject a contract whose stable references do not resolve here.

    Declared-but-absent relationship types are legal; unknown excluded master
    entities are not.  Requirement sets may name entity types absent from this
    warehouse (they simply gate nothing).
    """
    excluded = contract["exclude_entity_ids"]
    if excluded:
        known = {r[0] for r in conn.execute(
            "SELECT DISTINCT canonical_id FROM in_entity_map WHERE canonical_id IN"
            f" ({_marks(excluded)})", excluded)}
        if known != set(excluded):
            raise _bad_contract()
    # a master entity whose members disagree on entity type cannot be judged
    split = _scalar(
        conn,
        "SELECT COUNT(*) FROM (SELECT canonical_id FROM in_entity_map"
        " GROUP BY canonical_id HAVING COUNT(DISTINCT obj_type)>1)")
    if split:
        raise SGError("invalid-release-input",
                      "a master entity spans more than one entity type")


def _write_contract(conn, contract):
    conn.executemany(
        "INSERT INTO contract_allowed_relationships(relationship_type) VALUES(?)",
        [(t,) for t in contract["relationship_types"]])
    conn.executemany(
        "INSERT INTO contract_excluded_entities(entity_id) VALUES(?)",
        [(e,) for e in contract["exclude_entity_ids"]])
    for grp in contract["requirement_groups"]:
        conn.execute("INSERT INTO contract_groups(group_id) VALUES(?)",
                     (grp["id"],))
        for alt in grp["alternatives"]:
            conn.execute(
                "INSERT INTO contract_alternatives(alt_id, group_id, direction,"
                " min_peers) VALUES(?,?,?,?)",
                (alt["id"], grp["id"], alt["direction"],
                 alt["min_distinct_peers"]))
            conn.executemany(
                "INSERT INTO contract_alternative_relationship_types"
                "(alt_id, relationship_type) VALUES(?,?)",
                [(alt["id"], t) for t in alt["relationship_types"]])
            conn.executemany(
                "INSERT INTO contract_alternative_peer_types"
                "(alt_id, peer_type) VALUES(?,?)",
                [(alt["id"], t) for t in alt["peer_types"]])
    for entry in contract["named_requirement_sets"]:
        conn.execute(
            "INSERT INTO contract_requirement_sets(set_id, entity_type)"
            " VALUES(?,?)", (entry["id"], entry["entity_type"]))
        conn.executemany(
            "INSERT INTO contract_set_groups(set_id, group_id) VALUES(?,?)",
            [(entry["id"], gid) for gid in entry["groups"]])


def _write_meta(conn, master_path, revision, upstream_meta, contract):
    rows = [("release_schema", PACKAGE_SCHEMA),
            ("contract_schema", CONTRACT_SCHEMA),
            ("contract_sha256", contract["sha256"]),
            ("contract_json", json.dumps(contract, ensure_ascii=False,
                                         sort_keys=True)),
            ("master_revision", str(revision)),
            ("master_warehouse", os.path.abspath(master_path))]
    for key in _META_UPSTREAM_KEYS:
        if key in upstream_meta:
            rows.append((f"upstream_{key}", upstream_meta[key]))
    conn.executemany("INSERT INTO package_meta(key, value) VALUES(?,?)", rows)


# ------------------------------------------------------------------- wave 0 ----

def _init_entity_state(conn):
    bad = _scalar(conn, "SELECT COUNT(*) FROM ("
                        " SELECT canonical_id FROM in_entity_map"
                        " GROUP BY canonical_id HAVING COUNT(DISTINCT obj_type)>1)")
    if bad:
        raise SGError("invalid-release-input",
                      "a master entity spans more than one entity type")
    conn.execute(
        "INSERT INTO release_entity_state(entity_id, entity_type, status)"
        " SELECT canonical_id, MIN(obj_type), 'live' FROM in_entity_map"
        " GROUP BY canonical_id ORDER BY canonical_id")
    conn.execute(
        "UPDATE release_entity_state SET status='rejected', eviction_wave=0,"
        " reason='excluded-by-contract'"
        " WHERE entity_id IN (SELECT entity_id FROM contract_excluded_entities)")


def _init_relation_state(conn):
    # Wave 0 order follows the contract's own wording: explicit exclusions
    # first (with every relationship touching them), then disallowed
    # relationship types.  A row that is both keeps the first reason.
    conn.execute(
        "INSERT INTO release_relation_state(row_key, source_canon,"
        " relationship_type, target_canon, contribution_count, is_self_loop,"
        " status, eviction_wave, reason)"
        " SELECT r.row_key, r.source_canon, r.relationship_type, r.target_canon,"
        " r.contribution_count, r.is_self_loop,"
        " CASE WHEN EXISTS (SELECT 1 FROM release_entity_state e"
        "       WHERE e.entity_id=r.source_canon AND e.status!='live')"
        "        OR EXISTS (SELECT 1 FROM release_entity_state e"
        "       WHERE e.entity_id=r.target_canon AND e.status!='live')"
        "      THEN 'rejected'"
        "      WHEN NOT EXISTS (SELECT 1 FROM contract_allowed_relationships a"
        "       WHERE a.relationship_type=r.relationship_type) THEN 'rejected'"
        "      ELSE 'live' END,"
        " CASE WHEN EXISTS (SELECT 1 FROM release_entity_state e"
        "       WHERE e.entity_id=r.source_canon AND e.status!='live')"
        "        OR EXISTS (SELECT 1 FROM release_entity_state e"
        "       WHERE e.entity_id=r.target_canon AND e.status!='live')"
        "      THEN 0"
        "      WHEN NOT EXISTS (SELECT 1 FROM contract_allowed_relationships a"
        "       WHERE a.relationship_type=r.relationship_type) THEN 0"
        "      ELSE NULL END,"
        " CASE WHEN EXISTS (SELECT 1 FROM release_entity_state e"
        "       WHERE e.entity_id=r.source_canon AND e.status!='live')"
        "        OR EXISTS (SELECT 1 FROM release_entity_state e"
        "       WHERE e.entity_id=r.target_canon AND e.status!='live')"
        "      THEN 'endpoint-excluded'"
        "      WHEN NOT EXISTS (SELECT 1 FROM contract_allowed_relationships a"
        "       WHERE a.relationship_type=r.relationship_type)"
        "      THEN 'relationship-type-not-allowed'"
        "      ELSE NULL END"
        " FROM in_relations r ORDER BY r.row_key")


def _build_support(conn):
    """Materialize distinct-peer support exactly once (the initial account)."""
    conn.execute(
        "INSERT OR IGNORE INTO support(alt_id, entity_id, peer_id)"
        " SELECT a.alt_id, x.entity_id, x.peer_id FROM ("
        "   SELECT source_canon AS entity_id, target_canon AS peer_id,"
        "          relationship_type, 'out' AS direction"
        "     FROM release_relation_state"
        "     WHERE status='live' AND source_canon<>target_canon"
        "   UNION ALL"
        "   SELECT target_canon, source_canon, relationship_type, 'in'"
        "     FROM release_relation_state"
        "     WHERE status='live' AND source_canon<>target_canon"
        " ) x"
        " JOIN release_entity_state e ON e.entity_id=x.entity_id"
        " JOIN release_entity_state p ON p.entity_id=x.peer_id"
        " JOIN contract_requirement_sets rs ON rs.entity_type=e.entity_type"
        " JOIN contract_set_groups sg ON sg.set_id=rs.set_id"
        " JOIN contract_alternatives a ON a.group_id=sg.group_id"
        "      AND a.direction=x.direction"
        " JOIN contract_alternative_relationship_types art"
        "      ON art.alt_id=a.alt_id"
        "      AND art.relationship_type=x.relationship_type"
        " JOIN contract_alternative_peer_types apt ON apt.alt_id=a.alt_id"
        "      AND apt.peer_type=p.entity_type")
    conn.execute(
        "INSERT INTO support_count(entity_id, alt_id, c)"
        " SELECT entity_id, alt_id, COUNT(*) FROM support"
        " GROUP BY entity_id, alt_id")


# -------------------------------------------------------------- wave loop ----

def _temp(conn, name, ddl):
    conn.execute(f"DROP TABLE IF EXISTS {name}")
    conn.execute(f"CREATE TEMP TABLE {name}({ddl})")


def _run_wave(conn, wave: int):
    """Judge the current frontier and evict all failures of this wave at once.

    Returns ``(evicted, candidates, counter_rows_probed, lost_pairs)``.  The
    frontier is immutable while
    it is judged: nothing removed in this wave is visible to another
    judgement of the same wave, so a support gap one wave caused only appears
    in the next.  Work done here is proportional to the rows that changed,
    not to warehouse size: relation/entity status is probed by primary key,
    and peer removal decrements one indexed counter row at a time.
    """
    _temp(conn, "tmp_candidates", "entity_id TEXT PRIMARY KEY")
    _temp(conn, "tmp_failed", "entity_id TEXT PRIMARY KEY, entity_type TEXT")
    _temp(conn, "tmp_evicted_rel", "row_key TEXT PRIMARY KEY")
    _temp(conn, "tmp_lost_pairs", "entity_id TEXT, alt_id TEXT, peer_id TEXT")

    if wave == 1:
        # the first judgement: every live entity whose type has a requirement
        # set.  This is the initial account; later waves are delta-driven and
        # read only ``release_frontier``, which is indexed by primary key.
        conn.execute(
            "INSERT INTO tmp_candidates"
            " SELECT e.entity_id FROM release_entity_state e"
            " WHERE e.status='live' AND EXISTS ("
            "   SELECT 1 FROM contract_requirement_sets s"
            "   WHERE s.entity_type=e.entity_type) ORDER BY e.entity_id")
    else:
        conn.execute(
            "INSERT INTO tmp_candidates"
            " SELECT f.entity_id FROM release_frontier f"
            " JOIN release_entity_state e ON e.entity_id=f.entity_id"
            " WHERE e.status='live' ORDER BY f.entity_id")

    # counter rows this wave actually looks at: exactly one row per
    # (candidate, alternative).  Independent of any neighbourhood size.
    probed = _scalar(
        conn,
        "SELECT COUNT(*) FROM support_count sc"
        " JOIN tmp_candidates c ON c.entity_id=sc.entity_id"
        " WHERE sc.alt_id IN (SELECT alt_id FROM contract_alternatives)")
    conn.execute(
        "INSERT INTO tmp_failed"
        " SELECT e.entity_id, e.entity_type FROM release_entity_state e"
        " JOIN tmp_candidates c ON c.entity_id=e.entity_id"
        " JOIN contract_requirement_sets s ON s.entity_type=e.entity_type"
        " WHERE e.status='live' AND NOT EXISTS ("
        "   SELECT 1 FROM contract_set_groups sg"
        "   JOIN contract_alternatives a ON a.group_id=sg.group_id"
        "   LEFT JOIN support_count sc ON sc.entity_id=e.entity_id"
        "        AND sc.alt_id=a.alt_id"
        "   WHERE sg.set_id=s.set_id"
        "     AND COALESCE(sc.c,0) >= a.min_peers)"
        " ORDER BY e.entity_id")
    failed_count = _scalar(conn, "SELECT COUNT(*) FROM tmp_failed")
    candidate_count = _scalar(conn, "SELECT COUNT(*) FROM tmp_candidates")
    if failed_count == 0:
        conn.execute("DELETE FROM release_frontier")
        return 0, candidate_count, probed, 0

    # capture the measured frontier before removing anything
    conn.execute(
        "INSERT INTO eviction_alt_snapshot(entity_id, wave, group_id, alt_id,"
        " direction, distinct_peers, min_peers, met)"
        " SELECT f.entity_id, ?, sg.group_id, a.alt_id, a.direction,"
        "        COALESCE(sc.c,0), a.min_peers,"
        "        CASE WHEN COALESCE(sc.c,0) >= a.min_peers THEN 1 ELSE 0 END"
        " FROM tmp_failed f"
        " JOIN contract_requirement_sets rs ON rs.entity_type=f.entity_type"
        " JOIN contract_set_groups sg ON sg.set_id=rs.set_id"
        " JOIN contract_alternatives a ON a.group_id=sg.group_id"
        " LEFT JOIN support_count sc ON sc.entity_id=f.entity_id"
        "      AND sc.alt_id=a.alt_id"
        # only the groups that failed: at least one alternative under threshold
        " WHERE sg.group_id IN ("
        "   SELECT sg2.group_id FROM tmp_failed f2"
        "   JOIN contract_requirement_sets rs2 ON rs2.entity_type=f2.entity_type"
        "   JOIN contract_set_groups sg2 ON sg2.set_id=rs2.set_id"
        "   JOIN contract_alternatives a2 ON a2.group_id=sg2.group_id"
        "   LEFT JOIN support_count sc2 ON sc2.entity_id=f2.entity_id"
        "        AND sc2.alt_id=a2.alt_id"
        "   WHERE f2.entity_id=f.entity_id"
        "     AND COALESCE(sc2.c,0) < a2.min_peers)"
        " ORDER BY f.entity_id, sg.group_id, a.alt_id", (wave,))

    conn.execute(
        "INSERT INTO wave_entity_evictions(entity_id, wave, entity_type, reason)"
        " SELECT entity_id, ?, entity_type, 'requirement-not-met'"
        " FROM tmp_failed ORDER BY entity_id", (wave,))
    conn.execute(
        "UPDATE release_entity_state SET status='rejected', eviction_wave=?,"
        " reason='requirement-not-met'"
        " WHERE entity_id IN (SELECT entity_id FROM tmp_failed)", (wave,))

    # relations leave with their first evicted endpoint (both indexed)
    conn.execute(
        "INSERT INTO tmp_evicted_rel(row_key)"
        " SELECT row_key FROM release_relation_state"
        " WHERE source_canon IN (SELECT entity_id FROM tmp_failed)"
        "   AND status='live'")
    conn.execute(
        "INSERT OR IGNORE INTO tmp_evicted_rel(row_key)"
        " SELECT row_key FROM release_relation_state"
        " WHERE target_canon IN (SELECT entity_id FROM tmp_failed)"
        "   AND status='live'")
    conn.execute(
        "UPDATE release_relation_state SET status='rejected', eviction_wave=?,"
        " reason='endpoint-evicted'"
        " WHERE row_key IN (SELECT row_key FROM tmp_evicted_rel)", (wave,))

    # Each dead peer removes at most one (entity, alternative, peer) fact per
    # alternative.  The decrement is aggregated per (entity, alt) and applied
    # by support_count's primary key: the work is proportional to the
    # *removed* pairs, never to the surviving entity's fan-out or to warehouse
    # size.
    conn.execute(
        "INSERT INTO tmp_lost_pairs"
        " SELECT s.entity_id, s.alt_id, s.peer_id FROM support s"
        " JOIN tmp_failed f ON f.entity_id=s.peer_id"
        " WHERE s.entity_id NOT IN (SELECT entity_id FROM tmp_failed)")
    conn.execute(
        "DELETE FROM support WHERE EXISTS ("
        " SELECT 1 FROM tmp_lost_pairs x"
        " WHERE x.entity_id=support.entity_id"
        "   AND x.alt_id=support.alt_id"
        "   AND x.peer_id=support.peer_id)")
    conn.execute(
        "UPDATE support_count SET c = c - x.n FROM ("
        "  SELECT entity_id, alt_id, COUNT(*) AS n FROM tmp_lost_pairs"
        "  GROUP BY entity_id, alt_id) x"
        " WHERE support_count.entity_id=x.entity_id"
        "   AND support_count.alt_id=x.alt_id")
    # the failed entities' own remaining pairs go too (their counters are no
    # longer read, but the fact table must not retain dead rows)
    conn.execute(
        "DELETE FROM support WHERE entity_id IN"
        " (SELECT entity_id FROM tmp_failed)")
    conn.execute(
        "DELETE FROM support_count WHERE entity_id IN"
        " (SELECT entity_id FROM tmp_failed)")
    # Only an entity whose count actually moved can newly fail next wave.
    conn.execute("DELETE FROM release_frontier")
    conn.execute(
        "INSERT INTO release_frontier(entity_id)"
        " SELECT DISTINCT entity_id FROM tmp_lost_pairs")
    lost = _scalar(conn, "SELECT COUNT(*) FROM tmp_lost_pairs")
    return failed_count, candidate_count, probed, lost


# --------------------------------------------------------------- wave ledger ----

def _wave_counts(conn, wave):
    ents = _scalar(conn, "SELECT COUNT(*) FROM release_entity_state"
                         " WHERE eviction_wave=? AND status='rejected'", (wave,))
    rels = _scalar(conn, "SELECT COUNT(*) FROM release_relation_state"
                         " WHERE eviction_wave=? AND status='rejected'", (wave,))
    maps = _scalar(conn, "SELECT COUNT(*) FROM in_entity_map"
                         " WHERE canonical_id IN ("
                         "  SELECT entity_id FROM release_entity_state"
                         "  WHERE eviction_wave=? AND status='rejected')", (wave,))
    contribs = _scalar(conn, "SELECT COUNT(*) FROM in_contributions"
                             " WHERE row_key IN ("
                             "  SELECT row_key FROM release_relation_state"
                             "  WHERE eviction_wave=? AND status='rejected')",
                       (wave,))
    return ents, rels, maps, contribs


def _record_wave(conn, wave, phase, candidates=None, probed=None, lost=None):
    ents, rels, maps, contribs = _wave_counts(conn, wave)
    access = conn.access_snapshot()
    if candidates is None:
        candidates = _scalar(conn, "SELECT COUNT(*) FROM release_entity_state"
                                   " WHERE eviction_wave=? AND status='rejected'",
                             (wave,))
    if probed is None:
        probed = 0
    if lost is None:
        lost = 0
    conn.execute(
        "INSERT INTO release_waves(wave, phase, evicted_entities,"
        " evicted_relations, evicted_mappings, evicted_contributions,"
        " candidate_entities, probed_counter_rows, lost_support_pairs,"
        " access_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (wave, phase, ents, rels, maps, contribs, candidates, probed, lost,
         json.dumps(access, sort_keys=True)))
    conn.reset_acct()


# ---------------------------------------------------------- final surfaces ----

def _finalize_surfaces(conn):
    conn.execute(
        "INSERT INTO load_entities(obj_id, obj_type, canonical_id)"
        " SELECT m.obj_id, m.obj_type, m.canonical_id FROM in_entity_map m"
        " JOIN release_entity_state e ON e.entity_id=m.canonical_id"
        " WHERE e.status='loaded' ORDER BY m.obj_id")
    conn.execute(
        "INSERT INTO reject_entity_map(obj_id, obj_type, canonical_id,"
        " master_entity_id, eviction_wave, reason)"
        " SELECT m.obj_id, m.obj_type, m.canonical_id, e.entity_id,"
        " e.eviction_wave, e.reason FROM in_entity_map m"
        " JOIN release_entity_state e ON e.entity_id=m.canonical_id"
        " WHERE e.status='rejected' ORDER BY m.obj_id")

    conn.execute(
        "INSERT INTO load_relations(row_key, source_canon, relationship_type,"
        " target_canon, contribution_count, is_self_loop)"
        " SELECT row_key, source_canon, relationship_type, target_canon,"
        " contribution_count, is_self_loop"
        " FROM release_relation_state WHERE status='loaded' ORDER BY row_key")
    conn.execute(
        "INSERT INTO reject_relations(row_key, source_canon, relationship_type,"
        " target_canon, contribution_count, is_self_loop, eviction_wave, reason,"
        " evicted_endpoints_json)"
        " SELECT row_key, source_canon, relationship_type, target_canon,"
        " contribution_count, is_self_loop, eviction_wave, reason, "
        " '[]'"
        " FROM release_relation_state WHERE status='rejected' ORDER BY row_key")

    conn.execute(
        "INSERT INTO load_contributions(relationship_id, source_id, target_id,"
        " relationship_type, source_canon, target_canon, row_key, is_self_loop,"
        " modified_key, modified_raw)"
        " SELECT c.relationship_id, c.source_id, c.target_id,"
        " c.relationship_type, c.source_canon, c.target_canon, c.row_key,"
        " c.is_self_loop, c.modified_key, c.modified_raw"
        " FROM in_contributions c JOIN release_relation_state r"
        "   ON r.row_key=c.row_key"
        " WHERE r.status='loaded' ORDER BY c.relationship_id")
    conn.execute(
        "INSERT INTO reject_contributions(relationship_id, source_id, target_id,"
        " relationship_type, source_canon, target_canon, row_key, is_self_loop,"
        " modified_key, modified_raw, eviction_wave, reason)"
        " SELECT c.relationship_id, c.source_id, c.target_id,"
        " c.relationship_type, c.source_canon, c.target_canon, c.row_key,"
        " c.is_self_loop, c.modified_key, c.modified_raw,"
        " r.eviction_wave, r.reason"
        " FROM in_contributions c JOIN release_relation_state r"
        "   ON r.row_key=c.row_key"
        " WHERE r.status='rejected' ORDER BY c.relationship_id")

    _endpoint_evidence(conn)


def _endpoint_evidence(conn):
    """Record, per rejected relation, the endpoints that left the same wave.

    One batched join, no per-row round trip: for each rejected relation row we
    emit the evicted endpoints whose wave equals that row's wave.
    """
    conn.execute(
        "UPDATE reject_relations SET evicted_endpoints_json=COALESCE(("
        "  SELECT json_group_array(entity_id) FROM ("
        "    SELECT entity_id FROM release_entity_state s"
        "    WHERE s.entity_id=reject_relations.source_canon"
        "      AND s.status='rejected'"
        "      AND s.eviction_wave=reject_relations.eviction_wave"
        "    UNION"
        "    SELECT entity_id FROM release_entity_state s"
        "    WHERE s.entity_id=reject_relations.target_canon"
        "      AND s.status='rejected'"
        "      AND s.eviction_wave=reject_relations.eviction_wave)), '[]')"
        " WHERE EXISTS (SELECT 1 FROM release_entity_state s"
        "  WHERE s.entity_id=reject_relations.source_canon"
        "    AND s.status='rejected'"
        "    AND s.eviction_wave=reject_relations.eviction_wave)"
        "    OR EXISTS (SELECT 1 FROM release_entity_state s"
        "  WHERE s.entity_id=reject_relations.target_canon"
        "    AND s.status='rejected'"
        "    AND s.eviction_wave=reject_relations.eviction_wave)")


# ------------------------------------------------------------- verification ----

def _verify_partition(conn):
    for load, reject, source in (
            ("load_entities", "reject_entity_map", "in_entity_map"),
            ("load_relations", "reject_relations", "in_relations"),
            ("load_contributions", "reject_contributions", "in_contributions")):
        total = _scalar(conn, f"SELECT COUNT(*) FROM {source}")
        loaded = _scalar(conn, f"SELECT COUNT(*) FROM {load}")
        rejected = _scalar(conn, f"SELECT COUNT(*) FROM {reject}")
        if loaded + rejected != total:
            raise SGError("internal-invariant",
                          "release rows do not partition the input")
    dangling = _scalar(
        conn,
        "SELECT COUNT(*) FROM load_relations r"
        " WHERE NOT EXISTS (SELECT 1 FROM release_entity_state s"
        "   WHERE s.entity_id=r.source_canon AND s.status='loaded')"
        "    OR NOT EXISTS (SELECT 1 FROM release_entity_state s"
        "   WHERE s.entity_id=r.target_canon AND s.status='loaded')")
    if dangling:
        raise SGError("internal-invariant",
                      "a loaded relation has an unloaded endpoint")
    orphan = _scalar(
        conn,
        "SELECT COUNT(*) FROM load_contributions c"
        " WHERE NOT EXISTS (SELECT 1 FROM load_relations r"
        "   WHERE r.row_key=c.row_key)")
    if orphan:
        raise SGError("internal-invariant",
                      "a loaded contribution has no loaded relation")
    mismatch = _scalar(
        conn,
        "SELECT COUNT(*) FROM load_relations r"
        " WHERE r.contribution_count <> (SELECT COUNT(*) FROM load_contributions c"
        "   WHERE c.row_key=r.row_key)")
    if mismatch:
        raise SGError("internal-invariant",
                      "loaded relation contribution count does not match")
    missing_member = _scalar(
        conn,
        "SELECT COUNT(*) FROM in_entity_map m"
        " JOIN release_entity_state e ON e.entity_id=m.canonical_id"
        " WHERE e.status='loaded' AND NOT EXISTS ("
        "   SELECT 1 FROM load_entities l WHERE l.obj_id=m.obj_id)")
    if missing_member:
        raise SGError("internal-invariant",
                      "a loaded entity lost a member mapping")
    # the persisted support account must still agree with its counter rows
    drift = _scalar(
        conn,
        "SELECT COUNT(*) FROM support_count sc"
        " JOIN release_entity_state e ON e.entity_id=sc.entity_id"
        " WHERE e.status!='rejected' AND sc.c <> (SELECT COUNT(*) FROM support s"
        "   WHERE s.entity_id=sc.entity_id AND s.alt_id=sc.alt_id)")
    if drift:
        raise SGError("internal-invariant",
                      "support facts and running counters disagree")
    residue = _scalar(
        conn,
        "SELECT COUNT(*) FROM support s JOIN release_entity_state e"
        "   ON e.entity_id=s.entity_id"
        " WHERE e.status='rejected'")
    if residue:
        raise SGError("internal-invariant",
                      "support facts reference a rejected entity")


_DIGEST_TABLES = (
    ("load_entities", ("obj_id", "obj_type", "canonical_id")),
    ("load_relations", ("row_key", "source_canon", "relationship_type",
                        "target_canon", "contribution_count", "is_self_loop")),
    ("load_contributions", ("relationship_id", "source_id", "target_id",
                            "relationship_type", "source_canon", "target_canon",
                            "row_key", "is_self_loop", "modified_key",
                            "modified_raw")),
    ("reject_entity_map", ("obj_id", "obj_type", "canonical_id",
                           "master_entity_id", "eviction_wave", "reason")),
    ("reject_relations", ("row_key", "source_canon", "relationship_type",
                          "target_canon", "contribution_count", "is_self_loop",
                          "eviction_wave", "reason",
                          "evicted_endpoints_json")),
    ("reject_contributions", ("relationship_id", "source_id", "target_id",
                              "relationship_type", "source_canon",
                              "target_canon", "row_key", "is_self_loop",
                              "modified_key", "modified_raw", "eviction_wave",
                              "reason")),
    ("release_waves", ("wave", "phase", "evicted_entities",
                       "evicted_relations", "evicted_mappings",
                       "evicted_contributions", "candidate_entities",
                       "probed_counter_rows", "lost_support_pairs")),
    ("wave_entity_evictions", ("entity_id", "wave", "entity_type", "reason")),
    ("eviction_alt_snapshot", ("entity_id", "wave", "group_id", "alt_id",
                               "direction", "distinct_peers", "min_peers",
                               "met")),
    ("release_entity_state", ("entity_id", "entity_type", "status",
                              "eviction_wave", "reason")),
    ("release_relation_state", ("row_key", "source_canon", "relationship_type",
                                "target_canon", "contribution_count",
                                "is_self_loop", "status", "eviction_wave",
                                "reason")),
)


def _release_digest(conn) -> str:
    h = hashlib.sha256()
    for table, cols in _DIGEST_TABLES:
        h.update(b"\x00" + table.encode("utf-8"))
        order = ", ".join(cols)
        cur = conn.execute(f"SELECT {order} FROM {table} ORDER BY {order}")
        while True:
            batch = cur.fetchmany(1000)
            if not batch:
                break
            for row in batch:
                h.update(b"\x00" + canon(list(row)))
    return h.hexdigest()


def _record_access(conn):
    for phase_name, tables in conn.access_snapshot().items():
        for table, kinds in tables.items():
            for kind, count in kinds.items():
                conn.execute(
                    "INSERT INTO release_access(phase, table_name, kind, count)"
                    " VALUES(?,?,?,?)", (phase_name, table, kind, count))


# -------------------------------------------------------------------- receipt ----

def _count(conn, table):
    return _scalar(conn, f"SELECT COUNT(*) FROM {table}")


def receipt(path: str) -> dict:
    conn = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return receipt_from_conn(conn, path=path)
    finally:
        conn.close()


def receipt_from_conn(conn, path=None) -> dict:
    meta = {r["key"]: r["value"] for r in conn.execute(
        "SELECT key, value FROM package_meta")}
    waves = []
    for r in conn.execute(
            "SELECT wave, phase, evicted_entities, evicted_relations,"
            " evicted_mappings, evicted_contributions, candidate_entities,"
            " probed_counter_rows, lost_support_pairs, access_json"
            " FROM release_waves ORDER BY wave"):
        item = {k: r[k] for k in
                ("wave", "phase", "evicted_entities", "evicted_relations",
                 "evicted_mappings", "evicted_contributions",
                 "candidate_entities", "probed_counter_rows",
                 "lost_support_pairs")}
        item["access"] = json.loads(r["access_json"])
        waves.append(item)
    return {
        "package": path or meta.get("master_warehouse"),
        "status": "sealed",
        "release_schema": PACKAGE_SCHEMA,
        "master_revision": int(meta["master_revision"]),
        "contract_sha256": meta["contract_sha256"],
        "release_digest": meta.get("release_digest"),
        "wave_count": int(meta.get("wave_count", "0")),
        "upstream": {
            "codename": meta.get("upstream_codename"),
            "t_key": meta.get("upstream_t_key"),
            "principal": meta.get("upstream_principal"),
            "policy_digest": meta.get("upstream_policy_digest"),
            "package_digest_sha256": meta.get(
                "upstream_package_digest_sha256"),
            "warehouse_instance_id": meta.get(
                "upstream_warehouse_instance_id"),
        },
        "counts": {
            "input": {
                "entities": _count(conn, "in_entity_map"),
                "relations": _count(conn, "in_relations"),
                "contributions": _count(conn, "in_contributions"),
            },
            "load": {
                "entities": _count(conn, "load_entities"),
                "relations": _count(conn, "load_relations"),
                "contributions": _count(conn, "load_contributions"),
            },
            "reject": {
                "entities": _count(conn, "reject_entity_map"),
                "relations": _count(conn, "reject_relations"),
                "contributions": _count(conn, "reject_contributions"),
            },
        },
        "waves": waves,
    }
