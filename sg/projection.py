"""Per-principal isolated projection store.

Each (collection, time view, principal, policy digest) gets its OWN SQLite
file, generated from the protected source. Redacted original values are never
copied into this file: hidden properties are dropped and hidden array elements
are stored as NULL. Search indexes are built afterwards from projected values
only, so a hidden term can never match, count, sort, or surface in an error.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3

from .util import SGError, parse_time, dt_to_key
from . import store as S
from . import markings as M
from .redact import redact_object

PROJ_SCHEMA = """
CREATE TABLE objects (
    obj_id        TEXT PRIMARY KEY,
    obj_type      TEXT NOT NULL,
    modified_key  INTEGER NOT NULL,
    modified_raw  TEXT NOT NULL,
    doc_json      TEXT NOT NULL,
    redacted_json TEXT NOT NULL
);
CREATE TABLE search_terms (
    obj_id TEXT NOT NULL,
    field  TEXT NOT NULL,
    kind   TEXT NOT NULL,
    value  TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_terms ON search_terms(obj_id, field, kind, value);
CREATE INDEX ix_terms_lookup ON search_terms(field, kind, value);
CREATE TABLE edges (
    relationship_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    modified_key INTEGER NOT NULL
);
CREATE INDEX ix_edges_src ON edges(source_id);
CREATE INDEX ix_edges_tgt ON edges(target_id);
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SEARCH_FIELDS = ("pattern", "name", "description", "labels")
_SENTINEL = object()


def projection_path(directory: str, codename: str, t_key: int,
                    principal: str, digest: str) -> str:
    safe_p = principal.replace(os.sep, "_")
    return os.path.join(directory, f"proj_{codename}__t{t_key}__{safe_p}__{digest[:12]}.sqlite")


def open_projection(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        raise SGError("projection-missing",
                      "no projection for this collection/time/principal/policy; run project first")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------- building ----

def build_projection(src: sqlite3.Connection, dst_path: str, codename: str,
                     t_raw: str, principal: str, policy: dict, digest: str) -> dict:
    """Stream the source store into a new isolated projection file.

    The destination is built in a temp file and atomically renamed, so a crash
    never leaves a half-projection that could be mistaken for a success.
    """
    t_key = dt_to_key(parse_time(t_raw))
    if principal not in policy["principals"]:
        raise SGError("unknown-principal", f"principal {principal} is not registered in policy")
    allowed = policy["principals"][principal]
    tmp_path = dst_path + ".tmp"
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)
    if os.path.exists(dst_path):
        raise SGError("projection-exists",
                      "a projection with this exact identity already exists; refusing to overwrite")
    conn = sqlite3.connect(tmp_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(PROJ_SCHEMA)
    stats = {"visible": 0, "suppressed": 0, "edges": 0}
    try:
        visible_identities = {}  # obj_id -> modified_key (visible only)
        identity_rows = S.list_identities(src, codename)
        for ident in identity_rows:
            obj_id = ident["obj_id"]
            picked = S.select_version(src, codename, obj_id, t_key)
            if picked["status"] != "available":
                stats["suppressed"] += 1
                continue
            row = picked["row"]
            obj = json.loads(row["raw_json"])
            gran_rows = S.granular_for(src, codename, obj_id, row["modified_key"])
            parsed_gran = [(g["marking_ref"], g["selector"], json.loads(g["tokens_json"]))
                           for g in gran_rows]
            ok, blocked, blocked_refs, _reason = M.visible_for_principal(
                obj, parsed_gran, allowed)
            if not ok:
                stats["suppressed"] += 1
                continue
            projected, redacted = redact_object(obj, blocked, blocked_refs)
            # identity/version fields are guaranteed present (checked at ingest)
            for must in ("type", "id", "modified"):
                if must not in projected:
                    raise SGError("internal-invariant",
                                  "identity field missing after projection")
            conn.execute(
                "INSERT INTO objects(obj_id, obj_type, modified_key, modified_raw,"
                " doc_json, redacted_json) VALUES(?,?,?,?,?,?)",
                (obj_id, row["obj_type"], row["modified_key"], row["modified_raw"],
                 json.dumps(projected, ensure_ascii=False),
                 json.dumps(redacted, ensure_ascii=False)))
            visible_identities[obj_id] = row["modified_key"]
            stats["visible"] += 1
            _index_terms(conn, obj_id, projected)

        # relationships: the relationship row AND both endpoints must be visible
        for ident in identity_rows:
            obj_id = ident["obj_id"]
            picked = S.select_version(src, codename, obj_id, t_key)
            if picked["status"] != "available" or picked["row"]["obj_type"] != "relationship":
                continue
            if obj_id not in visible_identities:
                continue
            endpoints = S.relationship_endpoints(
                src, codename, picked["row"]["modified_key"], obj_id)
            src_id = endpoints.get("source")
            tgt_id = endpoints.get("target")
            # hidden/missing endpoint: no match, and its identity is never echoed
            if not src_id or not tgt_id:
                continue
            if src_id not in visible_identities or tgt_id not in visible_identities:
                continue
            conn.execute(
                "INSERT INTO edges(relationship_id, source_id, target_id, modified_key)"
                " VALUES(?,?,?,?)",
                (obj_id, src_id, tgt_id, picked["row"]["modified_key"]))
            stats["edges"] += 1

        signing_key = os.urandom(32)
        meta = {
            "codename": codename,
            "t_raw": t_raw,
            "t_key": str(t_key),
            "principal": principal,
            "policy_digest": digest,
            "signing_key": signing_key.hex(),
            "schema": "stix-gate-projection/1",
        }
        for key, value in meta.items():
            conn.execute("INSERT INTO meta(key, value) VALUES(?,?)", (key, value))
        conn.commit()
        conn.close()
        conn = None
        os.replace(tmp_path, dst_path)  # atomic publish
    except Exception:
        # Close the writer first so the temp file is not held open, then
        # remove every artifact: a half-built file must never remain under a
        # name that could be mistaken for a sealed projection.
        if conn is not None:
            conn.close()
        for stale in (tmp_path, dst_path):
            if os.path.exists(stale):
                os.unlink(stale)
        raise
    return stats


def _index_terms(conn, obj_id: str, projected: dict) -> None:
    """Index projected values only. NULL/redacted positions produce no term."""
    rows = []
    for field in SEARCH_FIELDS:
        if field not in projected:
            continue  # hidden field behaves exactly like a non-existent one
        value = projected[field]
        if field == "labels":
            if not isinstance(value, list):
                continue
            for element in value:
                if element is None:
                    continue  # redacted array slot: never indexed
                if isinstance(element, str):
                    rows.append((obj_id, field, "exact", element))
        elif isinstance(value, str):
            rows.append((obj_id, field, "exact", value))
    conn.executemany(
        "INSERT OR IGNORE INTO search_terms(obj_id, field, kind, value) VALUES(?,?,?,?)",
        rows)


# ---------------------------------------------------------------- tokens ----

def _key_of(conn) -> bytes:
    row = conn.execute("SELECT value FROM meta WHERE key='signing_key'").fetchone()
    return bytes.fromhex(row["value"])


def make_token(conn: sqlite3.Connection, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_key_of(conn), body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + sig).decode("ascii")


def verify_token(conn: sqlite3.Connection, token: str, expected: dict) -> dict:
    """Validate signature AND bind every pagination invariant."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        body, sig = raw[:-32], raw[-32:]
    except Exception:
        raise SGError("invalid-page-token", "malformed pagination token")
    if not hmac.compare_digest(hmac.new(_key_of(conn), body, hashlib.sha256).digest(), sig):
        raise SGError("invalid-page-token", "token signature does not verify")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise SGError("invalid-page-token", "token payload unreadable")
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    for key in ("codename", "t_key", "principal", "policy_digest"):
        if str(payload.get(key)) != str(meta.get(key)):
            raise SGError("page-context-mismatch",
                          "token is bound to a different collection, time, principal, or policy version")
    for key in ("field", "match", "term"):
        if payload.get(key) != expected.get(key):
            raise SGError("page-context-mismatch",
                          "token query conditions do not match the current request")
    return payload


# ---------------------------------------------------------------- search ----

def _like_escape(term: str) -> str:
    out = []
    for ch in term:
        if ch in ("\\", "%", "_"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def search(conn: sqlite3.Connection, field: str, match: str, term: str,
           limit: int, page_token: str = None):
    """Search strictly inside the authorized projection."""
    if field != "any" and field not in SEARCH_FIELDS:
        raise SGError("unsupported-field", "field is not searchable in this profile")
    if match not in ("exact", "substring"):
        raise SGError("unsupported-match", "match must be exact or substring")
    if not isinstance(term, str):
        raise SGError("invalid-term", "search term must be a string")
    expected = {"field": field, "match": match, "term": term}
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    for key in ("codename", "t_key", "principal", "policy_digest"):
        expected[key] = meta[key]

    if page_token:
        payload = verify_token(conn, page_token, expected)
        last_id = payload["last_id"]
    else:
        last_id = None

    where = []
    args = []
    if field != "any":
        where.append("t.field=?")
        args.append(field)
    if match == "exact":
        where.append("t.kind='exact' AND t.value=?")
        args.append(term)
    else:
        where.append("t.kind='exact' AND t.value LIKE ? ESCAPE '\\'")
        args.append("%" + _like_escape(term) + "%")
    if last_id is not None:
        where.append("t.obj_id > ?")
        args.append(last_id)
    sql = ("SELECT DISTINCT t.obj_id, o.doc_json, o.redacted_json FROM search_terms t"
           " JOIN objects o ON o.obj_id=t.obj_id WHERE " + " AND ".join(where)
           + " ORDER BY t.obj_id LIMIT ?")
    args.append(limit + 1)
    rows = conn.execute(sql, args).fetchall()

    items = []
    for r in rows[:limit]:
        items.append({
            "id": r["obj_id"],
            "object": json.loads(r["doc_json"]),
            "redacted": json.loads(r["redacted_json"]),
        })
    next_token = None
    if len(rows) > limit:
        payload = dict(expected)
        payload["last_id"] = rows[limit - 1]["obj_id"]
        next_token = make_token(conn, payload)
    return {
        "query": {"field": field, "match": match, "term": term},
        "hits": len(items),
        "has_more": next_token is not None,
        "next_page_token": next_token,
        "items": items,
    }


# ------------------------------------------------------------ references ----

def references(conn: sqlite3.Connection, obj_id: str, direction: str):
    """Upstream/downstream edges. Only edges with both endpoints visible exist."""
    if direction not in ("upstream", "downstream", "both"):
        raise SGError("unsupported-direction", "direction must be upstream, downstream or both")
    exists = conn.execute("SELECT 1 FROM objects WHERE obj_id=?", (obj_id,)).fetchone()
    if not exists:
        # hidden or missing: uniform non-match, no echo of anything
        return {"id": obj_id, "visible": False, "upstream": [], "downstream": [],
                "upstream_count": 0, "downstream_count": 0}
    out = {"id": obj_id, "visible": True, "upstream": [], "downstream": [],
           "upstream_count": 0, "downstream_count": 0}
    if direction in ("downstream", "both"):
        rows = conn.execute(
            "SELECT relationship_id, target_id FROM edges WHERE source_id=?"
            " ORDER BY relationship_id", (obj_id,)).fetchall()
        out["downstream"] = [{"relationship_id": r["relationship_id"],
                              "target_id": r["target_id"]} for r in rows]
        out["downstream_count"] = len(rows)
    if direction in ("upstream", "both"):
        rows = conn.execute(
            "SELECT relationship_id, source_id FROM edges WHERE target_id=?"
            " ORDER BY relationship_id", (obj_id,)).fetchall()
        out["upstream"] = [{"relationship_id": r["relationship_id"],
                            "source_id": r["source_id"]} for r in rows]
        out["upstream_count"] = len(rows)
    return out


def get_object(conn: sqlite3.Connection, obj_id: str):
    row = conn.execute(
        "SELECT doc_json, redacted_json FROM objects WHERE obj_id=?", (obj_id,)).fetchone()
    if not row:
        return None
    return {"object": json.loads(row["doc_json"]),
            "redacted": json.loads(row["redacted_json"])}
