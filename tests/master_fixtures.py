#!/usr/bin/env python3
"""Synthetic projection-package generator for master-warehouse verification.

Everything here is fabricated data (object ids like ``indicator--A``), never
real intelligence.  The generator writes a standalone SQLite file with the
same on-disk schema as ``sg projection`` + ``sg export``, so the master
warehouse can be built from it without touching any protected source store.

Two shapes are supported:

* the small hand-specified region (A..E plus three edges), optionally with
  ``N`` fully disconnected entities/edges/verdicts appended for the
  access-scope scale check;
* extra edges used by the self-loop / blocking-evidence test cases.

Run:  python3 -I tests/master_fixtures.py <output.sqlite> [--scale N]
"""
import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sg.projection import PROJ_SCHEMA  # noqa: E402

TS = "2026-01-01T00:00:00Z"
TKEY = 1767225600000000


def _add_object(conn, obj_type, obj_id, doc):
    conn.execute(
        "INSERT INTO objects(obj_id, obj_type, modified_key, modified_raw,"
        " doc_json, redacted_json) VALUES(?,?,?,?,?,?)",
        (obj_id, obj_type, TKEY, TS,
         json.dumps(doc, ensure_ascii=False), json.dumps(doc, ensure_ascii=False)))


def _add_edge(conn, rid, source, target, rel_type, modified_key=TKEY):
    doc = {"type": "relationship", "id": rid, "modified": TS,
           "relationship_type": rel_type, "source_ref": source,
           "target_ref": target}
    _add_object(conn, "relationship", rid, doc)
    conn.execute("INSERT INTO edges(relationship_id, source_id, target_id,"
                 " modified_key) VALUES(?,?,?,?)",
                 (rid, source, target, modified_key))


def build_package(path: str, scale: int = 0, extra_edges=()) -> dict:
    if os.path.exists(path):
        os.unlink(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(PROJ_SCHEMA)
    entities = ["indicator--A", "indicator--B", "indicator--C",
                "indicator--D", "indicator--E"]
    for eid in entities:
        _add_object(conn, "indicator", eid,
                    {"type": "indicator", "id": eid, "modified": TS,
                     "pattern": f"[file:name = '{eid}']"})
    edges = [
        ("relationship--R1", "indicator--A", "indicator--E", "indicates"),
        ("relationship--R2", "indicator--C", "indicator--E", "indicates"),
        ("relationship--R3", "indicator--E", "indicator--C", "indicates"),
    ]
    edges.extend(extra_edges)
    for rid, s, t, rt in edges:
        _add_edge(conn, rid, s, t, rt)

    # ---- scale filler: a huge, fully disconnected partition ----
    for i in range(scale):
        eid = f"indicator--Z{i:06d}"
        _add_object(conn, "indicator", eid,
                    {"type": "indicator", "id": eid, "modified": TS,
                     "pattern": f"[file:name = 'z{i}']"})
        # two filler entities per block with an edge unrelated to A..E
        eid2 = f"indicator--Y{i:06d}"
        _add_object(conn, "indicator", eid2,
                    {"type": "indicator", "id": eid2, "modified": TS})
        rid = f"relationship--ZEDGE{i:06d}"
        _add_edge(conn, rid, eid, eid2, "indicates")
        # a pre-existing same verdict pair inside the filler partition
        vid_s = f"verdict--ZS{i:06d}"
        vid_d = f"verdict--ZD{i:06d}"
        # adjudications are NOT projection data; they arrive via batches.
        # The scale batches are produced by build_scale_batches().
        _ = (vid_s, vid_d)

    meta = {"codename": "C-SYNTH", "t_raw": "2026-02-01T00:00:00Z",
            "t_key": str(TKEY), "principal": "carol",
            "policy_digest": "synthetic-digest",
            "signing_key": "00" * 32, "schema": "stix-gate-projection/1"}
    for k, v in meta.items():
        conn.execute("INSERT INTO meta(key, value) VALUES(?,?)", (k, v))
    conn.commit()
    conn.close()
    return {"path": path, "entities": len(entities) + 2 * scale,
            "edges": len(edges) + scale}


def build_scale_batches(path_prefix: str, scale: int):
    """Write the batch files that activate the filler partition's verdicts."""
    # One big initial filler batch (parent supplied by the caller's sequence).
    ops = []
    for i in range(scale):
        ops.append({"op": "put", "verdict_id": f"verdict--ZS{i:06d}",
                    "kind": "same", "a": f"indicator--Z{i:06d}",
                    "b": f"indicator--Y{i:06d}", "priority": 5})
        # a different verdict between adjacent filler blocks, always satisfied
        ops.append({"op": "put", "verdict_id": f"verdict--ZD{i:06d}",
                    "kind": "different", "a": f"indicator--Z{i:06d}",
                    "b": f"indicator--Z{(i + 1) % max(scale, 1):06d}"})
    return ops


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output")
    ap.add_argument("--scale", type=int, default=0)
    args = ap.parse_args()
    stats = build_package(args.output, args.scale)
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
