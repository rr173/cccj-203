"""Master-data revision impact analysis (read-only, deterministic).

Given two *committed* revisions ``s`` and ``e`` (``s <= e``) of one master
warehouse, this module produces an auditable impact report describing what
changed between the two boundary states and at every intermediate transition.

State construction never assumes the warehouse stores a full snapshot of an
arbitrary old revision.  Instead:

1. the revision-0 logical tables are reconstructed from the immutable base
   tables (``base_objects`` / ``base_edges``) using the documented build rules
   (every entity is its own canonical group; every base edge contributes to the
   relation key derived from its raw endpoints);
2. the committed change feed (``changes``) is replayed forward, one revision at
   a time, through the four logical tables.

The replay-to-head result must equal the physical head tables — tests assert
this invariant, which independently proves the replay is faithful.

Relation-key migration is never reported as a bare delete+insert pair: moved
contribution rows (identified by the stable original relationship id, its raw
endpoints and relationship type) form a bipartite graph between old and new
relation keys.  Connected components are reported as 1:1 migrations, one-to-many
splits, many-to-one merges or complex remaps, never guessing a unique
correspondence for fan-out cases.

Cumulative figures are computed strictly from the two boundary states.  The sum
of per-transition absolute deltas is retained only as an explicit churn
cross-check, never substituted for the net result.  Nothing in the report claims
that an adjudication *caused* a change: only associative facts observable between
adjacent committed revisions are stated.

Detail rows are produced by generators: per-transition working sets are
discarded as soon as the transition has been emitted, so process memory does not
grow linearly with the total number of detail lines.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from .master import (
    InstrumentedConnection,
    T_ENTITY,
    T_REL,
    T_CONTRIB,
    T_VERDICT,
    TABLE_ORDER,
    _row_key,
    connect,
)
from .util import SGError

REPORT_VERSION = "stix-gate-impact/1"
SORT_KEY_VERSION = "impact-sort-1"

# Detail line families, also used as the documented --filter-kind values.
KIND_OBJECT = "object"
KIND_RELATION = "relation"
KIND_MIGRATION = "migration"
KIND_CONTRIBUTION = "contribution"
FILTER_KINDS = ("all", KIND_OBJECT, KIND_RELATION, KIND_MIGRATION, KIND_CONTRIBUTION)
FILTER_SCOPES = ("all", "transitions", "cumulative")

_REV_WIDTH = 12
_CUM_REV = "0" * _REV_WIDTH

# Explanatory note carried verbatim in every cumulative block.  The report never
# attributes a change to a particular verdict; it only states observations.
OBSERVATION_NOTE = (
    "associative facts observed between adjacent committed revisions only; "
    "no individual adjudication is asserted to have caused any change")


# ----------------------------------------------------------- token machinery ----

def _signing_key(conn) -> bytes:
    """Derive a per-warehouse HMAC key.

    Prefer the projection signing key copied into ``package_meta`` at build
    time; fall back to a key derived from the sealed package digest so the
    mechanism never depends on a particular meta row being present.
    """
    row = conn.execute(
        "SELECT value FROM package_meta WHERE key='signing_key'").fetchone()
    if row is not None:
        try:
            return bytes.fromhex(row["value"])
        except ValueError:
            pass
    digest = conn.execute(
        "SELECT value FROM package_meta WHERE key='package_digest_sha256'"
    ).fetchone()
    seed = digest["value"] if digest is not None else "master-impact-fallback"
    return hashlib.sha256(("impact:" + seed).encode("utf-8")).digest()


def make_page_token(conn: InstrumentedConnection, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    sig = hmac.new(_signing_key(conn), body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + sig).decode("ascii")


def verify_page_token(conn: InstrumentedConnection, token: str, expected: dict) -> dict:
    """Validate the HMAC and every binding (warehouse, interval, filters, size)."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        body, sig = raw[:-32], raw[-32:]
    except Exception:
        raise SGError("invalid-page-token", "malformed pagination token")
    if not hmac.compare_digest(
            hmac.new(_signing_key(conn), body, hashlib.sha256).digest(), sig):
        raise SGError("invalid-page-token", "token signature does not verify")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise SGError("invalid-page-token", "token payload unreadable")
    for key in ("v", "wh", "s", "e", "scope", "kind", "rev", "size"):
        if payload.get(key) != expected.get(key):
            raise SGError("page-context-mismatch",
                          "token is bound to a different warehouse, revision"
                          " interval, filter or page size")
    return payload


# ------------------------------------------------------------- identification ----

def warehouse_identity(conn) -> dict:
    meta = {r["key"]: r["value"]
            for r in conn.execute("SELECT key, value FROM package_meta")}
    head = conn.execute(
        "SELECT MAX(revision) AS r FROM revisions").fetchone()["r"]
    return {
        "report": "stix-gate-master-impact",
        "report_version": REPORT_VERSION,
        "sort_key_version": SORT_KEY_VERSION,
        "warehouse": {
            "warehouse_instance_id":
                meta.get("warehouse_instance_id")
                or "legacy:" + str(meta.get("package_digest_sha256")),
            "package_digest_sha256": meta.get("package_digest_sha256"),
            "codename": meta.get("codename"),
            "warehouse_schema": meta.get("warehouse_schema"),
            "head_revision": head,
            "base_entity_count": _maybe_int(meta.get("base_entity_count")),
            "base_edge_count": _maybe_int(meta.get("base_edge_count")),
        },
    }


def _maybe_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def validate_interval(conn, start: int, end: int) -> int:
    if isinstance(start, bool) or isinstance(end, bool) \
            or not isinstance(start, int) or not isinstance(end, int):
        raise SGError("unknown-revision", "revision numbers must be integers")
    if start < 0 or end < 0:
        raise SGError("unknown-revision", "revision numbers must be non-negative")
    head = conn.execute(
        "SELECT MAX(revision) AS r FROM revisions").fetchone()["r"]
    if start > head or end > head:
        raise SGError("unknown-revision",
                      "one or both revisions are not committed in this warehouse")
    if start > end:
        raise SGError("reversed-range",
                      "start revision must not be greater than end revision")
    return head


# ------------------------------------------------------------- replay state ----

class _State:
    """Mutable logical-table state plus cheap running counters.

    The four dictionaries hold one snapshot worth of rows — the same order of
    magnitude as an existing ``read_all`` call.  Detail records are never
    accumulated here; per-transition records are emitted and discarded.
    """

    def __init__(self):
        self.t1 = {}  # obj_id -> row dict
        self.t2 = {}  # row_key -> row dict
        self.t3 = {}  # relationship_id -> row dict
        self.t4 = {}  # verdict_id -> row dict
        self.canon_counts = {}  # canonical_id -> member count

    def group_count(self) -> int:
        return len(self.canon_counts)


def build_revision_zero(conn) -> _State:
    """Reconstruct the revision-0 logical tables from immutable base tables.

    This is the documented build behaviour: each entity is its own canonical
    group, and each accepted base edge contributes under a key derived from its
    raw endpoints.  No historical snapshot table is read.
    """
    state = _State()
    for r in conn.execute(
            "SELECT obj_id, obj_type FROM base_objects ORDER BY obj_id"):
        state.t1[r["obj_id"]] = {
            "obj_id": r["obj_id"], "obj_type": r["obj_type"],
            "canonical_id": r["obj_id"]}
        state.canon_counts[r["obj_id"]] = 1

    aggregates = {}  # row_key -> list of t2 column values
    for e in conn.execute(
            "SELECT relationship_id, source_id, target_id, relationship_type,"
            " modified_key, modified_raw FROM base_edges"
            " ORDER BY relationship_id"):
        rk = _row_key(e["source_id"], e["relationship_type"], e["target_id"])
        sl = 1 if e["source_id"] == e["target_id"] else 0
        state.t3[e["relationship_id"]] = {
            "relationship_id": e["relationship_id"],
            "source_id": e["source_id"], "target_id": e["target_id"],
            "relationship_type": e["relationship_type"],
            "source_canon": e["source_id"], "target_canon": e["target_id"],
            "row_key": rk, "is_self_loop": sl,
            "modified_key": e["modified_key"],
            "modified_raw": e["modified_raw"]}
        aggregates.setdefault(rk, []).append(
            (e["source_id"], e["relationship_type"], e["target_id"], sl))

    for rk in sorted(aggregates):
        s, rel, t, sl = aggregates[rk][0]
        state.t2[rk] = {
            "row_key": rk, "source_canon": s, "relationship_type": rel,
            "target_canon": t,
            "contribution_count": len(aggregates[rk]),
            "is_self_loop": sl}
    return state


def _apply_change(state: _State, table: str, key: str, op: str, row):
    """Mutate state for one change record, maintaining running counters."""
    if table == T_ENTITY:
        old = state.t1.pop(key, None)
        if old is not None:
            bucket = state.canon_counts
            bucket[old["canonical_id"]] -= 1
            if bucket[old["canonical_id"]] == 0:
                del bucket[old["canonical_id"]]
        if op == "replace":
            state.t1[key] = row
            state.canon_counts[row["canonical_id"]] = \
                state.canon_counts.get(row["canonical_id"], 0) + 1
    elif table == T_REL:
        state.t2.pop(key, None)
        if op == "replace":
            state.t2[key] = row
    elif table == T_CONTRIB:
        state.t3.pop(key, None)
        if op == "replace":
            state.t3[key] = row
    elif table == T_VERDICT:
        state.t4.pop(key, None)
        if op == "replace":
            state.t4[key] = row


def _fetch_changes(conn, revision: int):
    """Change rows of one revision in the documented stable order."""
    order = {t: i for i, t in enumerate(TABLE_ORDER)}
    rows = conn.execute(
        "SELECT * FROM changes WHERE revision=? ORDER BY change_seq",
        (revision,)).fetchall()
    return sorted(rows, key=lambda r: (order[r["table_name"]], r["row_key"]))


# ------------------------------------------------------------- component DSU ----

class _Graph:
    """Bipartite old-key/new-key graph with side-preserving connected parts.

    A relation key can participate on BOTH sides (the key survives the
    transition while some of its contributions leave and others stay), so side
    membership is tracked independently of the union-find nodes.
    """

    def __init__(self):
        self.parent = {}
        self.old_side = set()
        self.new_side = set()

    def _find(self, x):
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != x:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def add_node(self, key, side):
        if key not in self.parent:
            self.parent[key] = key
        if side == "old":
            self.old_side.add(key)
        else:
            self.new_side.add(key)

    def link(self, a, b):
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            # deterministic tie break; component identity is recomputed below
            if ra > rb:
                ra, rb = rb, ra
            self.parent[rb] = ra

    def components(self):
        groups = {}
        for key in self.parent:
            groups.setdefault(self._find(key), []).append(key)
        out = []
        for keys in groups.values():
            old = sorted(k for k in keys if k in self.old_side)
            new = sorted(k for k in keys if k in self.new_side)
            n_old, n_new = len(old), len(new)
            if n_old == 1 and n_new == 1 and old != new:
                kind = "migrated"
            elif n_old == 1 and n_new == 1 and old == new:
                kind = "retained"
            elif n_old == 1 and n_new > 1:
                kind = "split"
            elif n_old > 1 and n_new == 1:
                kind = "merge"
            else:
                kind = "complex_remap"
            out.append({"component_kind": kind, "old_keys": old,
                        "new_keys": new})
        out.sort(key=lambda c: (c["old_keys"][0] if c["old_keys"]
                                else c["new_keys"][0],
                                c["new_keys"][0] if c["new_keys"] else ""))
        return out


# ---------------------------------------------------- per-transition analysis ----

def _boundary_counters(state: _State) -> dict:
    return {
        "entity_groups": state.group_count(),
        "relation_rows": len(state.t2),
        "contribution_total": len(state.t3),
        "self_loop_rows": sum(1 for r in state.t2.values() if r["is_self_loop"]),
    }


def _analyze_transition(state: _State, rows, revision: int) -> dict:
    """Build the structured impact record of one adjacent revision pair."""
    by_table = {t: [] for t in TABLE_ORDER}
    for r in rows:
        by_table[r["table_name"]].append(r)

    # ---- object mapping changes (T1) ----
    included, exited, primary_changed = [], [], []
    for r in by_table[T_ENTITY]:
        before = state.t1.get(r["row_key"])
        after = json.loads(r["row_json"]) if r["op"] == "replace" else None
        item_before = before["canonical_id"] if before else None
        item_after = after["canonical_id"] if after else None
        if before is None and after is not None:
            included.append({"obj_id": r["row_key"],
                             "before_canonical_id": None,
                             "after_canonical_id": item_after})
        elif before is not None and after is None:
            exited.append({"obj_id": r["row_key"],
                           "before_canonical_id": item_before,
                           "after_canonical_id": None})
        elif before is not None and after is not None:
            if before["canonical_id"] != after["canonical_id"]:
                primary_changed.append({
                    "obj_id": r["row_key"],
                    "before_canonical_id": item_before,
                    "after_canonical_id": item_after})
    included.sort(key=lambda x: x["obj_id"])
    exited.sort(key=lambda x: x["obj_id"])
    primary_changed.sort(key=lambda x: x["obj_id"])

    # ---- contribution-level migration graph (T3) ----
    # Every contribution row participating in a relation key that changes is a
    # vertex witness: surviving contributions keep the same key on both sides,
    # moved ones link old and new keys.  This keeps one-to-many splits and
    # many-to-one merges in a single component instead of fanning them out as
    # unrelated delete/insert pairs.
    graph = _Graph()
    moved = []  # entries whose row_key changed (or whose row appeared/vanished)
    t3_replaced = {}  # relationship id -> after row, for this revision
    t3_deleted = []
    for r in by_table[T_CONTRIB]:
        before = state.t3.get(r["row_key"])
        after = json.loads(r["row_json"]) if r["op"] == "replace" else None
        if after is not None:
            t3_replaced[after["relationship_id"]] = (before, after)
        else:
            t3_deleted.append(before)
    # surviving rows: contribution ids present before and not in this revision
    changed_ids = set(t3_replaced) | {b["relationship_id"]
                                      for b in t3_deleted if b is not None}
    surviving = [row for rid, row in state.t3.items() if rid not in changed_ids]
    for row in surviving:
        graph.add_node(row["row_key"], "old")
        graph.add_node(row["row_key"], "new")

    for rel_id, (before, after) in t3_replaced.items():
        if before is None:
            graph.add_node(after["row_key"], "new")
            moved.append({"relationship_id": rel_id,
                          "relationship_type": after["relationship_type"],
                          "original_source_id": after["source_id"],
                          "original_target_id": after["target_id"],
                          "old_row_key": None,
                          "new_row_key": after["row_key"],
                          "before": None,
                          "after": _contrib_coordinates(after)})
        elif before["row_key"] == after["row_key"]:
            graph.add_node(before["row_key"], "old")
            graph.add_node(before["row_key"], "new")
        else:
            graph.add_node(before["row_key"], "old")
            graph.add_node(after["row_key"], "new")
            graph.link(before["row_key"], after["row_key"])
            moved.append({"relationship_id": rel_id,
                          "relationship_type": after["relationship_type"],
                          "original_source_id": after["source_id"],
                          "original_target_id": after["target_id"],
                          "old_row_key": before["row_key"],
                          "new_row_key": after["row_key"],
                          "before": _contrib_coordinates(before),
                          "after": _contrib_coordinates(after)})
    for before in t3_deleted:
        if before is None:
            continue
        graph.add_node(before["row_key"], "old")
        moved.append({"relationship_id": before["relationship_id"],
                      "relationship_type": before["relationship_type"],
                      "original_source_id": before["source_id"],
                      "original_target_id": before["target_id"],
                      "old_row_key": before["row_key"],
                      "new_row_key": None,
                      "before": _contrib_coordinates(before),
                      "after": None})
    moved.sort(key=lambda m: (m["old_row_key"] or "",
                              m["new_row_key"] or "",
                              m["relationship_id"]))

    # ---- relation row changes (T2) ----
    t2_after = {}
    t2_changed_keys = set()
    for r in by_table[T_REL]:
        t2_changed_keys.add(r["row_key"])
        if r["op"] == "replace":
            row = json.loads(r["row_json"])
            t2_after[row["row_key"]] = row
            t2_changed_keys.add(row["row_key"])
    graph_nodes = set(graph.parent)
    appeared, disappeared, modified = [], [], []
    for key in sorted(t2_changed_keys):
        before = state.t2.get(key)
        after = t2_after.get(key)
        if before is None and after is not None:
            if key not in graph_nodes:
                appeared.append(key)
        elif before is not None and after is None:
            if key not in graph_nodes:
                disappeared.append(key)
        elif before is not None and after is not None:
            flags = []
            if before["contribution_count"] != after["contribution_count"]:
                flags.append("contribution_count")
            if before["is_self_loop"] != after["is_self_loop"]:
                flags.append("is_self_loop")
            if flags:
                modified.append({
                    "row_key": key,
                    "before_contribution_count": before["contribution_count"],
                    "after_contribution_count": after["contribution_count"],
                    "before_is_self_loop": before["is_self_loop"],
                    "after_is_self_loop": after["is_self_loop"],
                    "change_flags": flags})

    # assemble migration components with per-edge contribution evidence.
    # `links` covers every witness: surviving (k->k), moved (old->new) and
    # whole-key additions/removals, so each component lists all contribution
    # relationship ids pageable with their original coordinates.
    links = {}  # (old_key, new_key) -> sorted list of relationship ids
    for row in surviving:
        links.setdefault((row["row_key"], row["row_key"]), []).append(
            row["relationship_id"])
    for m in moved:
        links.setdefault((m["old_row_key"], m["new_row_key"]), []).append(
            m["relationship_id"])
    migrations = []
    for comp in graph.components():
        # A single key surviving unchanged on both sides is not a migration;
        # its node still had to participate in the graph to keep real split /
        # merge components connected, so it is dropped from the report only.
        if comp["component_kind"] == "retained":
            continue
        edges = []
        for (old_key, new_key), ids in links.items():
            if old_key in comp["old_keys"] and new_key in comp["new_keys"]:
                edges.append({"old_row_key": old_key,
                              "new_row_key": new_key,
                              "contribution_count": len(ids),
                              "relationship_ids": sorted(ids)})
        edges.sort(key=lambda e: (e["old_row_key"] or "",
                                  e["new_row_key"] or "",
                                  e["relationship_ids"]))
        comp_out = dict(comp)
        comp_out["edges"] = edges
        migrations.append(comp_out)
    migrations.sort(key=lambda c: (c["old_keys"][0] if c["old_keys"]
                                   else c["new_keys"][0],
                                   c["new_keys"][0] if c["new_keys"] else ""))

    # ---- per-key contribution count changes ----
    # Restricted to keys that physically changed in T2 this revision: graph
    # witnesses for retained keys still exist in both states and would
    # otherwise report a phantom 1->0/0->1 delta.
    per_key = []
    for key in sorted(t2_changed_keys):
        before = state.t2.get(key)
        after = t2_after.get(key)
        b = before["contribution_count"] if before else 0
        a = after["contribution_count"] if after else 0
        if a - b != 0:
            per_key.append({"row_key": key, "before": b, "after": a,
                            "delta": a - b})

    # ---- self-loop changes ----
    sl_changed = []
    seen_sl = set()
    for key in sorted(t2_changed_keys):
        before = state.t2.get(key)
        after = t2_after.get(key)
        if before is not None and after is not None \
                and before["is_self_loop"] != after["is_self_loop"]:
            entry = (key, key, before["is_self_loop"], after["is_self_loop"])
            seen_sl.add(entry)
            sl_changed.append({"old_row_key": key, "new_row_key": key,
                                "before_is_self_loop": before["is_self_loop"],
                                "after_is_self_loop": after["is_self_loop"]})
    for m in moved:
        if m["before"] is None or m["after"] is None:
            continue
        b_sl, a_sl = m["before"]["is_self_loop"], m["after"]["is_self_loop"]
        if b_sl != a_sl:
            entry = (m["old_row_key"], m["new_row_key"], b_sl, a_sl)
            if entry not in seen_sl:
                seen_sl.add(entry)
                sl_changed.append({
                    "old_row_key": m["old_row_key"],
                    "new_row_key": m["new_row_key"],
                    "before_is_self_loop": b_sl,
                    "after_is_self_loop": a_sl})

    return {
        "revision": revision,
        "parent_revision": revision - 1,
        "object_mapping": {"included": included, "exited": exited,
                           "primary_changed": primary_changed},
        "relation_keys": {"appeared": appeared, "disappeared": disappeared,
                          "modified": modified, "migrations": migrations},
        "moved_contributions": moved,
        "contribution_counts": {"per_key": per_key},
        "self_loops": {"changed": sl_changed},
        "counters_before": None,   # filled by the engine
        "counters_after": None,
    }


def _contrib_coordinates(row) -> dict:
    return {"source_canon": row["source_canon"],
            "target_canon": row["target_canon"],
            "row_key": row["row_key"],
            "is_self_loop": row["is_self_loop"],
            "modified_key": row["modified_key"],
            "modified_raw": row["modified_raw"]}


# ------------------------------------------------------------- sort key lines ----

def _rev_token(revision: int) -> str:
    return str(revision).zfill(_REV_WIDTH)


def _component_id(comp: dict) -> str:
    head_old = comp["old_keys"][0] if comp["old_keys"] else ""
    head_new = comp["new_keys"][0] if comp["new_keys"] else ""
    return head_old + "|" + head_new


def transition_lines(record: dict):
    """Yield deterministic JSONL detail lines for one transition record.

    All lines of one revision share the ``("10", rev, ...)`` block prefix, so
    a transition forms one contiguous interval in the global key order (its
    header always immediately precedes its detail lines).  This keeps simple
    seek pagination (``sort_key > last_page_key``) correct across families.
    """
    rk = _rev_token(record["revision"])
    yield {"line_kind": "transition_header", "scope": "transitions",
           "revision": record["revision"],
           "parent_revision": record["parent_revision"],
           "sort_key": ["10", rk, "00", ""]}
    for item in record["object_mapping"]["included"]:
        yield _object_line(record["revision"], item, "included")
    for item in record["object_mapping"]["exited"]:
        yield _object_line(record["revision"], item, "exited")
    for item in record["object_mapping"]["primary_changed"]:
        yield _object_line(record["revision"], item, "primary_changed")

    rk_changes = record["relation_keys"]
    for key in rk_changes["appeared"]:
        yield {"line_kind": "relation_key_change", "scope": "transitions",
               "revision": record["revision"], "change_kind": "appeared",
               "row_key": key, "sort_key": ["10", rk, "20", key]}
    for key in rk_changes["disappeared"]:
        yield {"line_kind": "relation_key_change", "scope": "transitions",
               "revision": record["revision"], "change_kind": "disappeared",
               "row_key": key, "sort_key": ["10", rk, "20", key]}
    for item in rk_changes["modified"]:
        yield {"line_kind": "relation_key_change", "scope": "transitions",
               "revision": record["revision"], "change_kind": "modified",
               "row_key": item["row_key"],
               "before_contribution_count": item["before_contribution_count"],
               "after_contribution_count": item["after_contribution_count"],
               "before_is_self_loop": item["before_is_self_loop"],
               "after_is_self_loop": item["after_is_self_loop"],
               "change_flags": item["change_flags"],
               "sort_key": ["10", rk, "20", item["row_key"]]}
    for comp in rk_changes["migrations"]:
        cid = _component_id(comp)
        yield {"line_kind": "relation_migration", "scope": "transitions",
               "revision": record["revision"],
               "component_kind": comp["component_kind"],
               "old_keys": comp["old_keys"], "new_keys": comp["new_keys"],
               "edges": comp["edges"],
               "sort_key": ["10", rk, "30", cid]}
    for m in record["moved_contributions"]:
        cid = (m["old_row_key"] or "") + "|" + (m["new_row_key"] or "")
        yield {"line_kind": "migration_contribution", "scope": "transitions",
               "revision": record["revision"],
               "relationship_id": m["relationship_id"],
               "relationship_type": m["relationship_type"],
               "original_source_id": m["original_source_id"],
               "original_target_id": m["original_target_id"],
               "old_row_key": m["old_row_key"],
               "new_row_key": m["new_row_key"],
               "before": m["before"], "after": m["after"],
               "sort_key": ["10", rk, "31", cid, m["relationship_id"]]}


def _object_line(revision, item, kind):
    rk = _rev_token(revision)
    return {"line_kind": "object_change", "scope": "transitions",
            "revision": revision, "change_kind": kind,
            "obj_id": item["obj_id"],
            "before_canonical_id": item["before_canonical_id"],
            "after_canonical_id": item["after_canonical_id"],
            "sort_key": ["10", rk, "10", item["obj_id"]]}


# --------------------------------------------------------------- cumulative ----

def _boundary_capture(state: _State) -> dict:
    """Narrow boundary facts: enough for endpoint diffs, not whole T1/T2 bodies.

    T3 rows are captured in full because their immutable raw coordinates
    (source/target/type/modified) are needed to explain boundary migrations
    even when the contribution is no longer present in the end state.
    """
    return {
        "t1": {k: v["canonical_id"] for k, v in state.t1.items()},
        "t2": {k: (v["contribution_count"], v["is_self_loop"])
               for k, v in state.t2.items()},
        "t3": {k: dict(v) for k, v in state.t3.items()},
        "counters": _boundary_counters(state),
    }


def _touch(tracked: dict, key: str, revision: int) -> None:
    """Record that a stable key was touched in a revision (deduped per rev)."""
    seen = tracked.setdefault(key, [])
    if not seen or seen[-1] != revision:
        seen.append(revision)


def _cumulative_record(start_capture: dict, end_state: _State,
                       touched_objects: dict, touched_relations: dict,
                       churn: dict) -> dict:
    end_t1 = {k: v["canonical_id"] for k, v in end_state.t1.items()}
    end_t2 = {k: (v["contribution_count"], v["is_self_loop"])
              for k, v in end_state.t2.items()}
    start_t1, start_t2 = start_capture["t1"], start_capture["t2"]

    included, exited, primary_changed, obj_reverted, obj_transient = \
        [], [], [], [], []
    for obj_id in sorted(set(start_t1) | set(end_t1)):
        s_can, e_can = start_t1.get(obj_id), end_t1.get(obj_id)
        if s_can is None and e_can is not None:
            included.append({"obj_id": obj_id, "before_canonical_id": None,
                             "after_canonical_id": e_can})
        elif s_can is not None and e_can is None:
            exited.append({"obj_id": obj_id, "before_canonical_id": s_can,
                           "after_canonical_id": None})
        elif s_can != e_can:
            primary_changed.append({"obj_id": obj_id,
                                    "before_canonical_id": s_can,
                                    "after_canonical_id": e_can})
        elif obj_id in touched_objects:
            obj_reverted.append(obj_id)
    # touched at some intermediate revision but absent from both boundaries
    obj_transient = sorted(k for k in touched_objects
                           if k not in start_t1 and k not in end_t1)

    # boundary-level migration graph from contribution row_key endpoints.
    # Surviving contributions register their key on both sides, so a key that
    # both retains and loses contributions stays in one split/merge component.
    graph = _Graph()
    moved = []
    links = {}
    start_t3 = {k: v["row_key"] for k, v in start_capture["t3"].items()}
    end_t3 = {k: v["row_key"] for k, v in end_state.t3.items()}
    for rel_id in sorted(set(start_t3) | set(end_t3)):
        old_key, new_key = start_t3.get(rel_id), end_t3.get(rel_id)
        before_row = start_capture["t3"].get(rel_id)
        if old_key == new_key:
            if old_key is not None:
                graph.add_node(old_key, "old")
                graph.add_node(old_key, "new")
                links.setdefault((old_key, old_key), []).append(rel_id)
            continue
        if old_key is not None:
            graph.add_node(old_key, "old")
        if new_key is not None:
            graph.add_node(new_key, "new")
        if old_key is not None and new_key is not None:
            graph.link(old_key, new_key)
        links.setdefault((old_key, new_key), []).append(rel_id)
        moved.append({
            "relationship_id": rel_id,
            "relationship_type": before_row["relationship_type"]
            if before_row else None,
            "original_source_id": before_row["source_id"]
            if before_row else None,
            "original_target_id": before_row["target_id"]
            if before_row else None,
            "old_row_key": old_key, "new_row_key": new_key,
            "before": _contrib_coordinates(before_row) if before_row else None,
            "after": _contrib_coordinates(end_state.t3[rel_id])
            if rel_id in end_state.t3 else None})
    migrations = []
    for comp in graph.components():
        if comp["component_kind"] == "retained":
            continue
        edges = []
        for (old_key, new_key), ids in links.items():
            if old_key in comp["old_keys"] and new_key in comp["new_keys"]:
                edges.append({"old_row_key": old_key,
                              "new_row_key": new_key,
                              "contribution_count": len(ids),
                              "relationship_ids": sorted(ids)})
        edges.sort(key=lambda e: (e["old_row_key"] or "",
                                  e["new_row_key"] or "",
                                  e["relationship_ids"]))
        comp_out = dict(comp)
        comp_out["edges"] = edges
        migrations.append(comp_out)
    migrations.sort(key=lambda c: (c["old_keys"][0] if c["old_keys"]
                                   else c["new_keys"][0],
                                   c["new_keys"][0] if c["new_keys"] else ""))
    graph_nodes = set(graph.parent)

    appeared, disappeared, modified, rel_reverted, rel_transient = \
        [], [], [], [], []
    for key in sorted(set(start_t2) | set(end_t2)):
        s_row, e_row = start_t2.get(key), end_t2.get(key)
        if s_row is None and e_row is not None:
            if key not in graph_nodes:
                appeared.append(key)
        elif s_row is not None and e_row is None:
            if key not in graph_nodes:
                disappeared.append(key)
        elif s_row is not None and e_row is not None and s_row != e_row:
            modified.append({"row_key": key,
                             "before_contribution_count": s_row[0],
                             "after_contribution_count": e_row[0],
                             "before_is_self_loop": s_row[1],
                             "after_is_self_loop": e_row[1],
                             "change_flags":
                                 _flags(s_row, e_row)})
        elif key in touched_relations:
            rel_reverted.append(key)
    rel_transient = sorted(k for k in touched_relations
                           if k not in start_t2 and k not in end_t2)

    sl_changed = []
    sl_seen = set()
    for key in sorted(set(start_t2) & set(end_t2)):
        if start_t2[key][1] != end_t2[key][1]:
            entry = (key, key, start_t2[key][1], end_t2[key][1])
            sl_seen.add(entry)
            sl_changed.append({"old_row_key": key, "new_row_key": key,
                               "before_is_self_loop": start_t2[key][1],
                               "after_is_self_loop": end_t2[key][1]})
    for m in moved:
        if m["before"] is None or m["after"] is None:
            continue
        if m["before"]["is_self_loop"] != m["after"]["is_self_loop"]:
            entry = (m["old_row_key"], m["new_row_key"],
                     m["before"]["is_self_loop"], m["after"]["is_self_loop"])
            if entry not in sl_seen:
                sl_seen.add(entry)
                sl_changed.append({"old_row_key": m["old_row_key"],
                                   "new_row_key": m["new_row_key"],
                                   "before_is_self_loop":
                                       m["before"]["is_self_loop"],
                                   "after_is_self_loop":
                                       m["after"]["is_self_loop"]})
    sl_changed.sort(key=lambda x: (x["old_row_key"] or "",
                                   x["new_row_key"] or ""))

    s_cnt, e_cnt = start_capture["counters"], _boundary_counters(end_state)
    cumulative = {
        "object_mapping": {
            "included": included, "exited": exited,
            "primary_changed": primary_changed,
            "touched": sorted(touched_objects),
            "touched_revisions": {k: touched_objects[k]
                                  for k in sorted(touched_objects)},
            "reverted": sorted(obj_reverted),
            "transient": obj_transient},
        "entity_groups": {
            "start_count": s_cnt["entity_groups"],
            "end_count": e_cnt["entity_groups"],
            "net_delta": e_cnt["entity_groups"] - s_cnt["entity_groups"],
            "transition_absolute_churn": churn["entity_groups"]},
        "relation_keys": {
            "appeared": appeared, "disappeared": disappeared,
            "modified": modified, "migrations": migrations,
            "touched": sorted(touched_relations),
            "touched_revisions": {k: touched_relations[k]
                                  for k in sorted(touched_relations)},
            "reverted": sorted(rel_reverted),
            "transient": rel_transient},
        "contribution_counts": {
            "start_total": s_cnt["contribution_total"],
            "end_total": e_cnt["contribution_total"],
            "net_delta": e_cnt["contribution_total"] - s_cnt["contribution_total"],
            "transition_absolute_churn": churn["contribution_total"]},
        "self_loops": {
            "start_count": s_cnt["self_loop_rows"],
            "end_count": e_cnt["self_loop_rows"],
            "net_delta": e_cnt["self_loop_rows"] - s_cnt["self_loop_rows"],
            "transition_absolute_churn": churn["self_loop_rows"],
            "changed": sl_changed},
        "observation_note": OBSERVATION_NOTE,
    }
    return cumulative, moved


def _flags(s_row, e_row):
    flags = []
    if s_row[0] != e_row[0]:
        flags.append("contribution_count")
    if s_row[1] != e_row[1]:
        flags.append("is_self_loop")
    return flags


def cumulative_lines(cumulative: dict, moved: list):
    """Yield deterministic JSONL lines for the cumulative section."""
    rk = _CUM_REV
    yield {"line_kind": "cumulative_header", "scope": "cumulative",
           "revision": None,
           "entity_groups": cumulative["entity_groups"],
           "contribution_counts": {
               k: v for k, v in cumulative["contribution_counts"].items()},
           "self_loops": {k: v for k, v in cumulative["self_loops"].items()
                          if k != "changed"},
           "observation_note": cumulative["observation_note"],
           "sort_key": ["20", rk, "00", ""]}
    om = cumulative["object_mapping"]
    for item in om["included"]:
        yield _cum_object_line("included", item, om, rk)
    for item in om["exited"]:
        yield _cum_object_line("exited", item, om, rk)
    for item in om["primary_changed"]:
        yield _cum_object_line("primary_changed", item, om, rk)
    for obj_id in om["reverted"]:
        yield {"line_kind": "object_touched", "scope": "cumulative",
               "revision": None, "obj_id": obj_id, "reverted": True,
               "transient": False,
               "boundary_canonical_id": _boundary_canon(obj_id, om),
               "touched_revisions": om["touched_revisions"][obj_id],
               "sort_key": ["20", rk, "11", obj_id]}
    for obj_id in om["transient"]:
        yield {"line_kind": "object_touched", "scope": "cumulative",
               "revision": None, "obj_id": obj_id, "reverted": False,
               "transient": True, "boundary_canonical_id": None,
               "touched_revisions": om["touched_revisions"][obj_id],
               "sort_key": ["20", rk, "12", obj_id]}
    rk_changes = cumulative["relation_keys"]
    for key in rk_changes["appeared"]:
        yield {"line_kind": "relation_key_change", "scope": "cumulative",
               "revision": None, "change_kind": "appeared",
               "row_key": key, "sort_key": ["20", rk, "20", key]}
    for key in rk_changes["disappeared"]:
        yield {"line_kind": "relation_key_change", "scope": "cumulative",
               "revision": None, "change_kind": "disappeared",
               "row_key": key, "sort_key": ["20", rk, "20", key]}
    for item in rk_changes["modified"]:
        out = dict(item)
        out.update({"line_kind": "relation_key_change",
                    "scope": "cumulative", "revision": None,
                    "change_kind": "modified",
                    "sort_key": ["20", rk, "20", item["row_key"]]})
        yield out
    for key in rk_changes["reverted"]:
        yield {"line_kind": "relation_touched", "scope": "cumulative",
               "revision": None, "row_key": key, "reverted": True,
               "transient": False,
               "touched_revisions": rk_changes["touched_revisions"][key],
               "sort_key": ["20", rk, "21", key]}
    for key in rk_changes["transient"]:
        yield {"line_kind": "relation_touched", "scope": "cumulative",
               "revision": None, "row_key": key, "reverted": False,
               "transient": True,
               "touched_revisions": rk_changes["touched_revisions"][key],
               "sort_key": ["20", rk, "22", key]}
    for comp in rk_changes["migrations"]:
        cid = _component_id(comp)
        out = dict(comp)
        out.update({"line_kind": "relation_migration",
                    "scope": "cumulative", "revision": None,
                    "sort_key": ["20", rk, "30", cid]})
        yield out
    for m in moved:
        cid = (m["old_row_key"] or "") + "|" + (m["new_row_key"] or "")
        out = dict(m)
        out.update({"line_kind": "migration_contribution",
                    "scope": "cumulative", "revision": None,
                    "sort_key": ["20", rk, "31", cid, m["relationship_id"]]})
        yield out
    for item in cumulative["self_loops"]["changed"]:
        cid = (item["old_row_key"] or "") + "|" + (item["new_row_key"] or "")
        out = dict(item)
        out.update({"line_kind": "self_loop_change",
                    "scope": "cumulative", "revision": None,
                    "sort_key": ["20", rk, "40", cid]})
        yield out


def _boundary_canon(obj_id, om):
    """Canonical id of a reverted object at both boundaries (identical)."""
    for bucket in (om["included"], om["exited"], om["primary_changed"]):
        for entry in bucket:
            if entry["obj_id"] == obj_id:
                return entry["before_canonical_id"]
    # touched-and-reverted objects never appear in the diff buckets; their
    # boundary canonical id is recorded in touched_revisions' scope via the
    # transition lines, so leave it None rather than guess.
    return None


def _cum_object_line(kind, item, om, rk):
    reverted = item["obj_id"] in om["reverted"]
    return {"line_kind": "object_change", "scope": "cumulative",
            "revision": None, "change_kind": kind,
            "obj_id": item["obj_id"],
            "before_canonical_id": item["before_canonical_id"],
            "after_canonical_id": item["after_canonical_id"],
            "reverted": reverted,
            "touched_revisions":
                om["touched_revisions"].get(item["obj_id"], []),
            "sort_key": ["20", rk, "10", item["obj_id"]]}


# ---------------------------------------------------------------- filtering ----

_LINE_FAMILY = {
    "transition_header": "all",
    "cumulative_header": "all",
    "object_change": KIND_OBJECT,
    "object_touched": KIND_OBJECT,
    "relation_key_change": KIND_RELATION,
    "relation_touched": KIND_RELATION,
    "relation_migration": KIND_MIGRATION,
    "migration_contribution": KIND_CONTRIBUTION,
    "self_loop_change": KIND_RELATION,
}


def _line_matches(line, scope, kind, revision):
    if scope == "transitions" and line["scope"] != "transitions":
        return False
    if scope == "cumulative" and line["scope"] != "cumulative":
        return False
    if revision is not None:
        if line["scope"] != "transitions" or line.get("revision") != revision:
            return False
    if kind != "all" and _LINE_FAMILY.get(line["line_kind"]) != kind:
        return False
    return True


# ------------------------------------------------------------- public engine ----

def _replay(conn, start, end):
    """Generator yielding replay events while reconstructing 0 -> end.

    Events:
      ("boundary-start", capture)  once, when state reaches ``start``
      ("transition", record)       for revisions 1..end, fully built (before and
                                   after counters included) before being yielded
      ("churn", churn_dict)        once, after the last transition
      ("boundary-end", state, touched_objects, touched_relations)  once
    """
    validate_interval(conn, start, end)
    state = build_revision_zero(conn)
    churn = {"entity_groups": 0, "contribution_total": 0,
             "self_loop_rows": 0}
    touched_objects = {}   # key -> sorted list of transition revisions
    touched_relations = {}
    if start == 0:
        yield "boundary-start", _boundary_capture(state)
    for revision in range(1, end + 1):
        rows = _fetch_changes(conn, revision)
        before = _boundary_counters(state)
        # analysis reads the pre-change state; touch tracking needs the same
        # pre-change lookups, so both happen before the changes are applied.
        record = _analyze_transition(state, rows, revision)
        record["counters_before"] = before
        if start < revision <= end:
            for r in rows:
                if r["table_name"] == T_ENTITY:
                    _touch(touched_objects, r["row_key"], revision)
                elif r["table_name"] == T_REL:
                    _touch(touched_relations, r["row_key"], revision)
                    if r["op"] == "replace":
                        new_key = json.loads(r["row_json"])["row_key"]
                        _touch(touched_relations, new_key, revision)
                elif r["table_name"] == T_CONTRIB:
                    old = state.t3.get(r["row_key"])
                    if old is not None:
                        _touch(touched_relations, old["row_key"], revision)
                    if r["op"] == "replace":
                        new_row = json.loads(r["row_json"])
                        _touch(touched_relations, new_row["row_key"], revision)
        for r in rows:
            row = json.loads(r["row_json"]) if r["row_json"] else None
            _apply_change(state, r["table_name"], r["row_key"], r["op"], row)
        after = _boundary_counters(state)
        record["counters_after"] = after
        if start < revision <= end:
            churn["entity_groups"] += abs(
                after["entity_groups"] - before["entity_groups"])
            churn["contribution_total"] += abs(
                after["contribution_total"] - before["contribution_total"])
            churn["self_loop_rows"] += abs(
                after["self_loop_rows"] - before["self_loop_rows"])
        if revision == start:
            yield "boundary-start", _boundary_capture(state)
        # only transitions strictly inside the interval are reported, even
        # though every revision up to ``end`` is still replayed for state.
        if start < revision <= end:
            yield "transition", record
    yield "churn", churn
    yield "boundary-end", state, touched_objects, touched_relations


def build_summary(master_path: str, start: int, end: int) -> dict:
    """Full deterministic JSON summary document for one revision interval."""
    conn = connect(master_path)
    conn.set_phase("impact")
    try:
        identity = warehouse_identity(conn)
        start_capture = None
        transitions = []
        end_bundle = None
        churn = None
        for phase, *payload in _replay(conn, start, end):
            if phase == "boundary-start":
                start_capture = payload[0]
            elif phase == "transition":
                transitions.append(_public_transition(payload[0]))
            elif phase == "churn":
                churn = payload[0]
            elif phase == "boundary-end":
                end_bundle = payload
        end_state, touched_objects, touched_relations = end_bundle
        cumulative, _moved = _cumulative_record(
            start_capture, end_state, touched_objects, touched_relations, churn)
        identity["interval"] = {
            "start_revision": start, "end_revision": end,
            "transition_revisions": list(range(start + 1, end + 1)),
            "zero_impact": start == end}
        identity["summary"] = {"transitions": transitions,
                               "cumulative": cumulative}
        return identity
    finally:
        conn.close()


def _public_transition(record: dict) -> dict:
    """Strip engine-only fields and add the counter before/after block."""
    b, a = record["counters_before"], record["counters_after"]
    out = {k: v for k, v in record.items()
           if k not in ("counters_before", "counters_after")}
    out["entity_groups"] = {"before_count": b["entity_groups"],
                            "after_count": a["entity_groups"],
                            "delta": a["entity_groups"] - b["entity_groups"]}
    out["contribution_counts"]["before_total"] = b["contribution_total"]
    out["contribution_counts"]["after_total"] = a["contribution_total"]
    out["contribution_counts"]["delta"] = \
        a["contribution_total"] - b["contribution_total"]
    out["self_loops"]["before_count"] = b["self_loop_rows"]
    out["self_loops"]["after_count"] = a["self_loop_rows"]
    out["self_loops"]["delta"] = a["self_loop_rows"] - b["self_loop_rows"]
    out["observation_note"] = OBSERVATION_NOTE
    # moved contribution coordinates live in the JSONL detail stream; the
    # summary keeps relationship id lists inside migration edges.
    del out["moved_contributions"]
    return out


def iter_detail_lines(master_path: str, start: int, end: int,
                      scope="all", kind="all", revision=None,
                      after_sort_key=None, max_lines=None):
    """Stream filtered, globally sorted JSONL detail lines.

    Pure generator: per-transition records are dropped once their lines have
    been yielded, and iteration stops as soon as ``max_lines`` have been
    produced.  Memory therefore does not grow with the total detail volume.
    """
    if scope not in FILTER_SCOPES:
        raise SGError("invalid-filter", "unknown scope filter")
    if kind not in FILTER_KINDS:
        raise SGError("invalid-filter", "unknown kind filter")
    if revision is not None:
        if isinstance(revision, bool) or not isinstance(revision, int) \
                or revision <= start or revision > end:
            raise SGError("invalid-filter",
                          "revision filter must name a transition inside the interval")
    conn = connect(master_path)
    conn.set_phase("impact")
    emitted = 0
    try:
        start_capture = None
        churn = None
        end_bundle = None
        for phase, *payload in _replay(conn, start, end):
            if phase == "boundary-start":
                start_capture = payload[0]
            elif phase == "churn":
                churn = payload[0]
            elif phase == "boundary-end":
                end_bundle = payload
            elif phase == "transition":
                record = payload[0]
                if not (start < record["revision"] <= end):
                    continue
                for line in transition_lines(record):
                    if not _line_matches(line, scope, kind, revision):
                        continue
                    if after_sort_key is not None \
                            and line["sort_key"] <= after_sort_key:
                        continue
                    yield line
                    emitted += 1
                    if max_lines is not None and emitted >= max_lines:
                        return
        end_state, touched_objects, touched_relations = end_bundle
        cumulative, moved = _cumulative_record(
            start_capture, end_state, touched_objects, touched_relations, churn)
        for line in cumulative_lines(cumulative, moved):
            if not _line_matches(line, scope, kind, revision):
                continue
            if after_sort_key is not None \
                    and line["sort_key"] <= after_sort_key:
                continue
            yield line
            emitted += 1
            if max_lines is not None and emitted >= max_lines:
                return
    finally:
        conn.close()


def read_page(master_path: str, start: int, end: int, page_size: int,
              scope="all", kind="all", revision=None, page_token=None):
    """Return one deterministic page plus a bound, signed next-page token."""
    if isinstance(page_size, bool) or not isinstance(page_size, int) \
            or page_size <= 0:
        raise SGError("invalid-filter", "page size must be a positive integer")
    conn = connect(master_path)
    conn.set_phase("impact")
    try:
        identity = warehouse_identity(conn)
        validate_interval(conn, start, end)
        wh_id = identity["warehouse"]["warehouse_instance_id"]
        expected = {"v": REPORT_VERSION, "wh": wh_id, "s": start, "e": end,
                    "scope": scope, "kind": kind, "rev": revision,
                    "size": page_size}
        after = None
        if page_token is not None:
            payload = verify_page_token(conn, page_token, expected)
            after = payload["after"]
        lines = []
        gen = iter_detail_lines(master_path, start, end, scope, kind,
                                revision, after_sort_key=after,
                                max_lines=page_size + 1)
        for line in gen:
            lines.append(line)
        page = lines[:page_size]
        has_more = len(lines) > page_size
        next_token = None
        if has_more:
            token_payload = dict(expected)
            token_payload["after"] = page[-1]["sort_key"]
            next_token = make_page_token(conn, token_payload)
        return {"page": page, "has_more": has_more,
                "next_page_token": next_token, "page_size": page_size,
                "returned": len(page),
                "report_version": REPORT_VERSION,
                "sort_key_version": SORT_KEY_VERSION,
                "warehouse_identity": identity["warehouse"],
                "interval": {"start_revision": start,
                             "end_revision": end}}
    finally:
        conn.close()
