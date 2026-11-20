"""Protected source store: staging, finalization, version selection.

One SQLite file holds every finalized collection. The file is the protected
repository: ordinary projections are written to *separate* files, and nothing
in this store is exposed through the analysis API.
"""
from __future__ import annotations

import json
import sqlite3

from .util import SGError, canon, iter_bundle_objects, parse_time, dt_to_key
from . import markings as M

SUPPORTED_TYPES = ("indicator", "malware", "relationship")

SCHEMA = """
CREATE TABLE IF NOT EXISTS stages (
    stage_id     TEXT PRIMARY KEY,
    received_at  TEXT NOT NULL,
    bundle_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stage_objects (
    stage_id   TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    obj_json   TEXT NOT NULL,
    PRIMARY KEY (stage_id, seq)
);
CREATE TABLE IF NOT EXISTS collections (
    codename    TEXT PRIMARY KEY,
    finalized_at TEXT NOT NULL,
    stage_list  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS markings (
    codename   TEXT NOT NULL,
    marking_id TEXT NOT NULL,
    canon_hex  TEXT NOT NULL,
    raw_json   TEXT NOT NULL,
    PRIMARY KEY (codename, marking_id)
);
CREATE TABLE IF NOT EXISTS versions (
    codename      TEXT NOT NULL,
    obj_type      TEXT NOT NULL,
    obj_id        TEXT NOT NULL,
    modified_key  INTEGER NOT NULL,
    modified_raw  TEXT NOT NULL,
    state         TEXT NOT NULL,
    revoked       INTEGER NOT NULL,
    conflicted    INTEGER NOT NULL DEFAULT 0,
    block_reason  TEXT,
    raw_json      TEXT NOT NULL,
    canon_hex     TEXT NOT NULL,
    PRIMARY KEY (codename, obj_id, modified_key, canon_hex)
);
CREATE TABLE IF NOT EXISTS granular_marks (
    codename   TEXT NOT NULL,
    obj_id     TEXT NOT NULL,
    modified_key INTEGER NOT NULL,
    marking_ref TEXT NOT NULL,
    selector   TEXT NOT NULL,
    tokens_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS object_refs (
    codename TEXT NOT NULL,
    obj_id   TEXT NOT NULL,
    modified_key INTEGER NOT NULL,
    ref_kind TEXT NOT NULL,
    ref_id   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS unsupported_refs (
    codename TEXT NOT NULL,
    obj_id   TEXT NOT NULL,
    modified_key INTEGER NOT NULL,
    field    TEXT NOT NULL,
    ref_id   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS malformed (
    codename TEXT NOT NULL,
    seq      INTEGER NOT NULL,
    reason   TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diagnostics (
    codename   TEXT NOT NULL,
    obj_id     TEXT,
    modified_key INTEGER,
    kind       TEXT NOT NULL,
    detail     TEXT NOT NULL,
    has_body   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_versions_lookup
    ON versions(codename, obj_id, modified_key);
CREATE INDEX IF NOT EXISTS idx_gran ON granular_marks(codename, obj_id, modified_key);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


# ---------------------------------------------------------------- stage ----

def stage_bundle(conn: sqlite3.Connection, stage_id: str, paths, received_at: str) -> int:
    """Receive whole bundles into a stage. All-or-nothing; no codename exists yet.

    NDJSON inputs are streamed line-by-line so corpus size never dictates
    resident memory. Any parse error rolls the whole stage back.
    """
    if conn.execute("SELECT 1 FROM stages WHERE stage_id=?", (stage_id,)).fetchone():
        raise SGError("stage_exists", f"stage {stage_id} already exists")
    existing_cn = conn.execute(
        "SELECT 1 FROM collections WHERE stage_list LIKE ?", (f"%{stage_id}%",)
    ).fetchone()
    if existing_cn:
        raise SGError("stage_frozen", "stage already bound to a finalized collection")
    total = 0
    try:
        conn.execute("INSERT INTO stages(stage_id, received_at, bundle_count) VALUES(?,?,?)",
                     (stage_id, received_at, len(paths)))
        batch = []
        for path in paths:
            for obj in iter_bundle_objects(path):  # generator for NDJSON
                batch.append((stage_id, total,
                              json.dumps(obj, ensure_ascii=False)))
                total += 1
                if len(batch) >= 500:
                    conn.executemany(
                        "INSERT INTO stage_objects(stage_id, seq, obj_json) VALUES(?,?,?)",
                        batch)
                    batch.clear()
        if batch:
            conn.executemany(
                "INSERT INTO stage_objects(stage_id, seq, obj_json) VALUES(?,?,?)", batch)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return total


# ------------------------------------------------------------- finalize ----

def _stage_union_temp(conn, stage_ids):
    """Copy staged objects into a temp table; returns nothing.

    The temp table keeps raw JSON inside SQLite and extracts identity columns
    exactly once, with an index, so finalization is O(n log n) and never holds
    the whole collection in Python memory.
    """
    conn.execute(
        "CREATE TEMP TABLE IF NOT EXISTS _incoming("
        " seq INTEGER PRIMARY KEY, oid TEXT, otype TEXT, obj_json TEXT)")
    conn.execute("DELETE FROM _incoming")
    for sid in stage_ids:
        conn.execute(
            "INSERT INTO _incoming(seq, oid, otype, obj_json)"
            " SELECT seq, json_extract(obj_json,'$.id'),"
            " json_extract(obj_json,'$.type'), obj_json"
            " FROM stage_objects WHERE stage_id=?", (sid,))
    conn.execute("CREATE INDEX IF NOT EXISTS ix_incoming_oid ON _incoming(oid)")


def _process_markings(conn, codename):
    """Stream marking definitions out of the temp table. Returns id sets."""
    seen, conflicted, rows = {}, set(), []
    for r in conn.execute(
            "SELECT seq, oid, obj_json FROM _incoming"
            " WHERE otype='marking-definition' ORDER BY seq"):
        obj = json.loads(r["obj_json"])
        mid = r["oid"]
        if not isinstance(mid, str):
            conn.execute(
                "INSERT INTO malformed(codename, seq, reason, raw_json) VALUES(?,?,?,?)",
                (codename, r["seq"], "marking-definition-missing-id", r["obj_json"]))
            conn.execute(
                "INSERT INTO diagnostics(codename, obj_id, modified_key, kind, detail, has_body)"
                " VALUES(?,?,?,?,?,?)",
                (codename, None, None, "malformed",
                 "marking-definition-missing-id", 1))
            continue
        chash = canon(obj).hex()
        if mid in seen and seen[mid] != chash:
            conflicted.add(mid)
        seen.setdefault(mid, chash)
        rows.append((mid, chash, r["obj_json"]))
    conn.executemany(
        "INSERT OR REPLACE INTO markings(codename, marking_id, canon_hex, raw_json)"
        " VALUES(?,?,?,?)",
        [(codename, mid, chash, raw) for (mid, chash, raw) in rows])
    for mid in conflicted:
        conn.execute(
            "INSERT INTO diagnostics(codename, obj_id, modified_key, kind, detail, has_body)"
            " VALUES(?,?,?,?,?,?)",
            (codename, mid, None, "marking-definition-conflict",
             "duplicate marking id with differing canonical content", 0))
    return set(seen), conflicted


def _process_one_identity(conn, codename, oid, otype, known_marks, conflicted_marks, stats):
    rows = conn.execute(
        "SELECT obj_json FROM _incoming WHERE oid=? ORDER BY seq", (oid,)).fetchall()
    parsed_versions = []
    for r in rows:
        obj = json.loads(r["obj_json"])
        raw = r["obj_json"]
        chash = canon(obj).hex()
        revoked = 1 if obj.get("revoked") is True else 0
        try:
            created, modified = obj.get("created"), obj.get("modified")
            if created is None or modified is None:
                raise SGError("missing-time", "created/modified required")
            ckey, mkey = dt_to_key(parse_time(created)), dt_to_key(parse_time(modified))
            if ckey > mkey:
                raise SGError("created-after-modified",
                              "created must not be later than modified")
        except SGError as exc:
            conn.execute(
                "INSERT INTO versions(codename, obj_type, obj_id, modified_key,"
                " modified_raw, state, revoked, conflicted, block_reason, raw_json, canon_hex)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (codename, otype, oid, -1, str(obj.get("modified")),
                 "invalid-time", revoked, 0, exc.code, raw, chash))
            conn.execute(
                "INSERT INTO diagnostics(codename, obj_id, modified_key, kind, detail, has_body)"
                " VALUES(?,?,?,?,?,?)",
                (codename, oid, None, "invalid-time", exc.code, 1))
            continue

        state = "supported" if otype in SUPPORTED_TYPES else "unsupported"
        block_reason, parsed_gran = None, []
        if state == "supported":
            block_reason, parsed_gran = M.resolve_object_block(
                obj, known_marks, conflicted_marks)
            if block_reason:
                conn.execute(
                    "INSERT INTO diagnostics(codename, obj_id, modified_key, kind, detail, has_body)"
                    " VALUES(?,?,?,?,?,?)",
                    (codename, oid, mkey, "object-blocked", block_reason, 1))
                stats["blocked"] += 1
        parsed_versions.append(
            (mkey, obj, raw, chash, revoked, state, block_reason,
             obj.get("modified"), parsed_gran))

    by_time = {}
    for item in parsed_versions:
        by_time.setdefault(item[0], set()).add(item[3])
    conflict_times = {k for k, hs in by_time.items() if len(hs) > 1}
    stats["conflicts"] += len(conflict_times)

    for (mkey, obj, raw, chash, revoked, state, block_reason,
         modified_raw, parsed_gran) in parsed_versions:
        conn.execute(
            "INSERT INTO versions(codename, obj_type, obj_id, modified_key,"
            " modified_raw, state, revoked, conflicted, block_reason, raw_json, canon_hex)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (codename, otype, oid, mkey, modified_raw, state, revoked,
             1 if mkey in conflict_times else 0, block_reason, raw, chash))
        stats["objects"] += 1
        if state == "unsupported":
            stats["unsupported"] += 1
        if revoked:
            stats["revoked"] += 1
            conn.execute(
                "INSERT INTO diagnostics(codename, obj_id, modified_key, kind, detail, has_body)"
                " VALUES(?,?,?,?,?,?)",
                (codename, oid, mkey, "revoked", "version revoked=true", 0))
        for ref, selector, tokens in parsed_gran:
            conn.execute(
                "INSERT INTO granular_marks(codename, obj_id, modified_key,"
                " marking_ref, selector, tokens_json) VALUES(?,?,?,?,?,?)",
                (codename, oid, mkey, ref, selector, json.dumps(tokens)))
        if state == "supported" and otype == "relationship":
            for kind, field in (("source", "source_ref"), ("target", "target_ref")):
                ref_id = obj.get(field)
                if isinstance(ref_id, str):
                    conn.execute(
                        "INSERT INTO object_refs(codename, obj_id, modified_key,"
                        " ref_kind, ref_id) VALUES(?,?,?,?,?)",
                        (codename, oid, mkey, kind, ref_id))
        # other business references: retained as unsupported provenance only
        for field, value in obj.items():
            if field.endswith("_ref") and field not in ("source_ref", "target_ref") \
                    and isinstance(value, str):
                conn.execute(
                    "INSERT INTO unsupported_refs(codename, obj_id, modified_key,"
                    " field, ref_id) VALUES(?,?,?,?,?)",
                    (codename, oid, mkey, field, value))
            if field.endswith("_refs") and isinstance(value, list) \
                    and field != "object_marking_refs":
                for ref_id in value:
                    if isinstance(ref_id, str):
                        conn.execute(
                            "INSERT INTO unsupported_refs(codename, obj_id, modified_key,"
                            " field, ref_id) VALUES(?,?,?,?,?)",
                            (codename, oid, mkey, field, ref_id))


def finalize(conn: sqlite3.Connection, codename: str, stage_ids, finalized_at: str,
             expected_marking_ids=None) -> dict:
    """Publish an immutable collection. A failure rolls back: no codename."""
    if conn.execute("SELECT 1 FROM collections WHERE codename=?", (codename,)).fetchone():
        raise SGError("collection_exists", f"collection {codename} already published")
    for sid in stage_ids:
        if not conn.execute("SELECT 1 FROM stages WHERE stage_id=?", (sid,)).fetchone():
            raise SGError("unknown_stage", f"stage {sid} was never fully received")
        if conn.execute(
                "SELECT 1 FROM collections WHERE stage_list LIKE ?",
                (f"%{sid}%",)).fetchone():
            raise SGError("stage_frozen", "stage already bound to another collection")

    try:
        conn.execute("BEGIN")
    except sqlite3.OperationalError:
        pass
    try:
        _stage_union_temp(conn, stage_ids)
        known_marks, conflicted_marks = _process_markings(conn, codename)
        if expected_marking_ids is not None:
            missing = set(expected_marking_ids) - known_marks
            if missing:
                raise SGError("policy-marking-missing",
                               "policy references marking ids absent from the collection")

        stats = {"objects": 0, "unsupported": 0, "malformed": 0,
                 "blocked": 0, "conflicts": 0, "revoked": 0}
        # distinct identities streamed one at a time from the indexed temp table
        identities = conn.execute(
            "SELECT DISTINCT oid, otype FROM _incoming"
            " WHERE otype != 'marking-definition'").fetchall()
        for ident in identities:
            oid, otype = ident["oid"], ident["otype"]
            if not isinstance(oid, str) or not oid or not isinstance(otype, str) or not otype:
                conn.execute(
                    "INSERT INTO diagnostics(codename, obj_id, modified_key, kind, detail, has_body)"
                    " VALUES(?,?,?,?,?,?)",
                    (codename, oid if isinstance(oid, str) else None, None,
                     "malformed", "missing-type-or-id", 1))
                stats["malformed"] += 1
                continue
            _process_one_identity(conn, codename, oid, otype,
                                  known_marks, conflicted_marks, stats)

        conn.execute(
            "INSERT INTO collections(codename, finalized_at, stage_list) VALUES(?,?,?)",
            (codename, finalized_at, json.dumps(list(stage_ids))))
        conn.commit()
        conn.execute("DROP TABLE IF EXISTS _incoming")
        stats["collection"] = codename
        stats["known_markings"] = sorted(known_marks)
        stats["conflicted_markings"] = sorted(conflicted_marks)
        return stats
    except Exception:
        conn.rollback()
        conn.execute("DROP TABLE IF EXISTS _incoming")
        raise


# --------------------------------------------------- versioned time view ----

def select_version(conn: sqlite3.Connection, codename: str, obj_id: str, t_key: int):
    """Pick the visible version of one identity at time t.

    Returns a dict with keys: status (available|revoked|conflict|not-found|
    unsupported|blocked), row, reason. Never falls back past a conflict or a
    revoked version.
    """
    rows = conn.execute(
        "SELECT * FROM versions WHERE codename=? AND obj_id=? AND modified_key<=?"
        " ORDER BY modified_key DESC, canon_hex",
        (codename, obj_id, t_key)).fetchall()
    if not rows:
        return {"status": "not-found", "row": None, "reason": "no version at or before t"}

    # group every candidate by its modified-time bucket
    groups = []
    current_key = None
    for row in rows:
        if row["modified_key"] != current_key:
            groups.append({"key": row["modified_key"], "rows": []})
            current_key = row["modified_key"]
        groups[-1]["rows"].append(row)

    top = groups[0]
    top_rows = top["rows"]
    if all(r["state"] == "invalid-time" for r in top_rows):
        return {"status": "not-found", "row": None,
                "reason": "only invalid-time versions exist"}

    # same identity + same modified time, differing canonical content
    if len({r["canon_hex"] for r in top_rows}) > 1:
        return {"status": "conflict", "row": top_rows[0],
                "reason": "same identity and modified time carry differing canonical content"}

    leader = top_rows[0]
    if leader["state"] == "unsupported":
        return {"status": "unsupported", "row": leader,
                "reason": "object type is not supported"}
    if leader["block_reason"]:
        return {"status": "blocked", "row": leader, "reason": leader["block_reason"]}

    if leader["revoked"]:
        # A revoked top version simply makes this time view unavailable; the
        # older history stays readable at its own (earlier) time points. Only
        # a same-time-bucket non-revoked sibling would contradict the revoke.
        sibling_live = any(not r["revoked"] for r in top_rows[1:])
        if sibling_live:
            return {"status": "conflict", "row": leader,
                    "reason": "same modified time carries both revoked and live content"}
        return {"status": "revoked", "row": leader,
                "reason": "revoked=true at this time view"}

    # Latest bucket is live. Recovery after a revoke is forbidden by this
    # profile: an earlier revoked bucket followed by revoked=false is a
    # business conflict, not an invented "restored" meaning.
    earlier_revoked = any(
        r["revoked"] for grp in groups[1:] for r in grp["rows"])
    if earlier_revoked:
        return {"status": "conflict", "row": leader,
                "reason": "a prior version was revoked; revoked=false afterwards is not a defined recovery"}

    return {"status": "available", "row": leader, "reason": None}


def list_identities(conn, codename: str):
    return conn.execute(
        "SELECT obj_type, obj_id, MIN(modified_key) AS first_key FROM versions"
        " WHERE codename=? AND state!='invalid-time' GROUP BY obj_id",
        (codename,)).fetchall()


def granular_for(conn, codename, obj_id, modified_key):
    return conn.execute(
        "SELECT marking_ref, selector, tokens_json FROM granular_marks"
        " WHERE codename=? AND obj_id=? AND modified_key=?",
        (codename, obj_id, modified_key)).fetchall()


def relationship_endpoints(conn, codename, modified_key, obj_id):
    out = {}
    for r in conn.execute(
            "SELECT ref_kind, ref_id FROM object_refs"
            " WHERE codename=? AND obj_id=? AND modified_key=?",
            (codename, obj_id, modified_key)):
        out[r["ref_kind"]] = r["ref_id"]
    return out


def diagnostics(conn, codename):
    return conn.execute(
        "SELECT obj_id, modified_key, kind, detail, has_body FROM diagnostics"
        " WHERE codename=? ORDER BY rowid", (codename,)).fetchall()


def get_raw(conn, codename, obj_id, modified_key=None):
    q = ("SELECT raw_json, modified_key FROM versions WHERE codename=? AND obj_id=?"
         " ORDER BY modified_key DESC")
    args = [codename, obj_id]
    if modified_key is not None:
        q = ("SELECT raw_json, modified_key FROM versions WHERE codename=? AND obj_id=?"
             " AND modified_key=?")
        args.append(modified_key)
    row = conn.execute(q, args).fetchone()
    if not row:
        row = conn.execute(
            "SELECT raw_json, NULL AS modified_key FROM malformed"
            " WHERE codename=? AND raw_json LIKE ?",
            (codename, f'%"{obj_id}"%')).fetchone()
    return row
