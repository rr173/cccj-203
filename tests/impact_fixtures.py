#!/usr/bin/env python3
"""Synthetic fixture for master-data revision impact analysis.

Everything here is fabricated data (object ids like ``indicator--A``).  The
fixture deliberately walks a small warehouse through every phenomenon the
impact report must explain, in a fixed batch sequence:

  rev 0  build: 7 entities, 8 edges (incl. one self loop and parallel edges)
  rev 1  B1  three-way merge A,B,C  (many-to-one relation migration, parallel
          edge aggregation, contribution replacement on an existing key)
  rev 2  B2  retract one verdict  -> split  (1:1 relation migration back)
  rev 3  B3  merge A,B  -> self loop appears
  rev 4  B4  retract -> split, self loop disappears  (rev 2 state restored:
          an explicit change-and-revert interval)
  rev 5  B5  merge C,D  -> one-to-many relation key split
  rev 6  B6  retract -> split the one-to-many back  (many-to-one re-merge)
  rev 7  B7  empty batch  -> legal zero-change revision

A hand-written expectation document lives next to this file in
``hand_expected/impact_expectations.json``; nothing here is generated from the
report implementation itself.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.master_fixtures import build_package  # noqa: E402
from sg import master as MD  # noqa: E402

TS = "2026-01-01T00:00:00Z"

# (relationship id, source, target, type).  R1/R2/R3 already exist in the base
# fixture package; R1/R6 are parallel base edges that aggregate onto one key
# when A and C merge; R7 is a base self loop.
EXTRA_EDGES = [
    ("relationship--R4", "indicator--A", "indicator--B", "indicates"),
    ("relationship--R5", "indicator--D", "indicator--F", "indicates"),
    ("relationship--R6", "indicator--C", "indicator--E", "refers-to"),
    ("relationship--R7", "indicator--G", "indicator--G", "indicates"),
    ("relationship--R8", "indicator--C", "indicator--E", "uses"),
]
EDGES = [
    ("relationship--R1", "indicator--A", "indicator--E", "indicates"),
    ("relationship--R2", "indicator--C", "indicator--E", "indicates"),
    ("relationship--R3", "indicator--E", "indicator--C", "indicates"),
] + EXTRA_EDGES


def write_batch(work, name, doc):
    path = os.path.join(work, name)
    with open(path, "wb") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    return path


def build_impact_warehouse(work: str) -> str:
    """Build the fixture package and replay the fixed batch sequence."""
    os.makedirs(work, exist_ok=True)
    pkg = os.path.join(work, "impact_pkg.sqlite")
    build_package(pkg, scale=0, extra_edges=EXTRA_EDGES)
    # build_package creates A..E plus the extra edges; add F and G entities.
    import sqlite3
    conn = sqlite3.connect(pkg)
    conn.row_factory = sqlite3.Row
    tkey = 1767225600000000
    for eid in ("indicator--F", "indicator--G"):
        conn.execute(
            "INSERT INTO objects(obj_id, obj_type, modified_key, modified_raw,"
            " doc_json, redacted_json) VALUES(?,?,?,?,?,?)",
            (eid, "indicator", tkey, TS,
             json.dumps({"type": "indicator", "id": eid, "modified": TS}),
             json.dumps({"type": "indicator", "id": eid, "modified": TS})))
    conn.commit()
    conn.close()

    mpath = os.path.join(work, "impact_master.sqlite")
    MD.build_master(pkg, mpath)

    # Fixed walk-through (every batch changes the effective state):
    #  B1 triple merge {A,B,C}: parallel-edge aggregation, many-to-one relation
    #     key migration, contribution replacement on an existing key, and a
    #     merged self loop (A<-B edge R4).
    #  B2 retract V-BC -> split: one-to-many key split back; V-AB keeps {A,B}.
    #  B3 retract V-AB -> split {A,B}: the R4 self loop disappears.
    #  B4 re-merge A,B via a new verdict id: R4 self loop reappears ->
    #     rev2..rev4 is an explicit change-and-revert interval for A/B and R4.
    #  B5 merge C,D -> one-to-many split of the C-side edge keys.
    #  B6 retract -> merge back: the inverse many-to-one re-merge.
    #  B7 empty batch -> legal zero-change revision header.
    batches = [
        ("B1", 0, [
            {"op": "put", "verdict_id": "V-AB", "kind": "same",
             "a": "indicator--A", "b": "indicator--B", "priority": 3},
            {"op": "put", "verdict_id": "V-BC", "kind": "same",
             "a": "indicator--B", "b": "indicator--C", "priority": 2}]),
        ("B2", 1, [
            {"op": "retract", "verdict_id": "V-BC"}]),
        ("B3", 2, [
            {"op": "retract", "verdict_id": "V-AB"}]),
        ("B4", 3, [
            {"op": "put", "verdict_id": "V-AB-again", "kind": "same",
             "a": "indicator--A", "b": "indicator--B", "priority": 3}]),
        ("B5", 4, [
            {"op": "put", "verdict_id": "V-CD", "kind": "same",
             "a": "indicator--C", "b": "indicator--D", "priority": 2}]),
        ("B6", 5, [
            {"op": "retract", "verdict_id": "V-CD"}]),
        ("B7", 6, []),
    ]
    for name, parent, ops in batches:
        doc = {"batch_id": name, "expected_parent": parent, "operations": ops}
        receipt = MD.apply_batch(mpath, json.dumps(doc).encode("utf-8"))
        assert receipt["published_revision"] == parent + 1, (name, receipt)
    return mpath


# Optional scale filler: N independent merge regions, each adding noise that
# the streaming/pagination tests walk through without growing memory.
def build_scaled_warehouse(work: str, scale: int) -> str:
    from tests.master_fixtures import build_package as _bp
    os.makedirs(work, exist_ok=True)
    pkg = os.path.join(work, "scale_pkg.sqlite")
    _bp(pkg, scale=0, extra_edges=EXTRA_EDGES)
    import sqlite3
    conn = sqlite3.connect(pkg)
    tkey = 1767225600000000
    for i in range(scale):
        for tag in ("P", "Q"):
            eid = f"indicator--{tag}{i:06d}"
            conn.execute(
                "INSERT INTO objects(obj_id, obj_type, modified_key,"
                " modified_raw, doc_json, redacted_json)"
                " VALUES(?,?,?,?,?,?)",
                (eid, "indicator", tkey, TS,
                 json.dumps({"type": "indicator", "id": eid, "modified": TS}),
                 json.dumps({"type": "indicator", "id": eid,
                             "modified": TS})))
        rid = f"relationship--S{i:06d}"
        conn.execute(
            "INSERT INTO objects(obj_id, obj_type, modified_key, modified_raw,"
            " doc_json, redacted_json) VALUES(?,?,?,?,?,?)",
            (rid, "relationship", tkey, TS,
             json.dumps({"type": "relationship", "id": rid, "modified": TS,
                         "relationship_type": "indicates",
                         "source_ref": f"indicator--P{i:06d}",
                         "target_ref": f"indicator--Q{i:06d}"}),
             json.dumps({"type": "relationship", "id": rid, "modified": TS,
                         "relationship_type": "indicates",
                         "source_ref": f"indicator--P{i:06d}",
                         "target_ref": f"indicator--Q{i:06d}"})))
        conn.execute("INSERT INTO edges(relationship_id, source_id, target_id,"
                     " modified_key) VALUES(?,?,?,?)",
                     (rid, f"indicator--P{i:06d}", f"indicator--Q{i:06d}",
                      tkey))
    conn.commit()
    conn.close()

    mpath = os.path.join(work, "scale_master.sqlite")
    MD.build_master(pkg, mpath)
    # one giant batch merges every filler pair -> scale transition changes
    ops = [{"op": "put", "verdict_id": f"V--PQ{i:06d}", "kind": "same",
            "a": f"indicator--P{i:06d}", "b": f"indicator--Q{i:06d}",
            "priority": 1} for i in range(scale)]
    doc = {"batch_id": "SCALE", "expected_parent": 0, "operations": ops}
    receipt = MD.apply_batch(mpath, json.dumps(doc).encode("utf-8"))
    assert receipt["published_revision"] == 1
    # second batch splits every pair back
    ops2 = [{"op": "retract", "verdict_id": f"V--PQ{i:06d}"}
            for i in range(scale)]
    doc2 = {"batch_id": "SCALEBACK", "expected_parent": 1, "operations": ops2}
    receipt2 = MD.apply_batch(mpath, json.dumps(doc2).encode("utf-8"))
    assert receipt2["published_revision"] == 2
    return mpath
