#!/usr/bin/env python3
"""Synthetic projection packages for master-release verification.

Everything is fabricated (ids such as ``indicator--I1``, relationship types
such as ``indicates``).  The generator writes a standalone SQLite file with
the schema ``sg export`` produces, so ``master-build`` can bind it without a
protected source store.  Large corpora are generated at test time and never
committed.

Run:  python3 -I tests/release_fixtures.py <out.sqlite> --scenario main
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
CONTRACT_SCHEMA = "stix-gate-master-release-contract/1"


def _add_object(conn, obj_type, obj_id, doc):
    body = json.dumps(doc, ensure_ascii=False)
    conn.execute(
        "INSERT INTO objects(obj_id, obj_type, modified_key, modified_raw,"
        " doc_json, redacted_json) VALUES(?,?,?,?,?,?)",
        (obj_id, obj_type, TKEY, TS, body, body))


def _add_edge(conn, rid, source, target, rel_type):
    doc = {"type": "relationship", "id": rid, "modified": TS,
           "relationship_type": rel_type, "source_ref": source,
           "target_ref": target}
    _add_object(conn, "relationship", rid, doc)
    conn.execute("INSERT INTO edges(relationship_id, source_id, target_id,"
                 " modified_key) VALUES(?,?,?,?)",
                 (rid, source, target, TKEY))


def write_projection(path, entities, edges):
    if os.path.exists(path):
        os.unlink(path)
    conn = sqlite3.connect(path)
    conn.executescript(PROJ_SCHEMA)
    for eid, etype in entities:
        _add_object(conn, etype, eid,
                    {"type": etype, "id": eid, "modified": TS,
                     "pattern": f"[file:name = '{eid}']"})
    for rid, src, tgt, rtype in edges:
        _add_edge(conn, rid, src, tgt, rtype)
    meta = {"codename": "C-RELEASE", "t_raw": "2026-02-01T00:00:00Z",
            "t_key": str(TKEY), "principal": "release",
            "policy_digest": "synthetic-release-digest",
            "signing_key": "11" * 32, "schema": "stix-gate-projection/1"}
    for k, v in meta.items():
        conn.execute("INSERT INTO meta(key, value) VALUES(?,?)", (k, v))
    conn.commit()
    conn.close()
    return path


# ------------------------------------------------------------------ scenarios ----

def main_scenario():
    """The documented fixture.

    * I1 -> I2 -> I3 -> I4: with "one out indicator peer" required, I4 goes in
      wave 1, then I3, I2, I1 one per wave; only I5/I6 (mutual) and I7 (self
      loop plus an edge to I5) survive.
    * Malware M1 has two *types* of allowed edge to the same peer I2 plus a
      self loop: one distinct peer only, so it leaves in wave 1 and its
      measured count is 1.
    * Malware M2 reaches two distinct peers through two different allowed
      relationship types, so both of its alternatives are satisfied.
    """
    entities = [(f"indicator--I{i}", "indicator") for i in range(1, 8)]
    entities += [("malware--M1", "malware"), ("malware--M2", "malware")]
    edges = [
        ("relationship--c1", "indicator--I1", "indicator--I2", "indicates"),
        ("relationship--c2", "indicator--I2", "indicator--I3", "indicates"),
        ("relationship--c3", "indicator--I3", "indicator--I4", "indicates"),
        ("relationship--p1", "indicator--I5", "indicator--I6", "indicates"),
        ("relationship--p2", "indicator--I6", "indicator--I5", "indicates"),
        ("relationship--s7", "indicator--I7", "indicator--I7", "indicates"),
        ("relationship--t7", "indicator--I7", "indicator--I5", "indicates"),
        # M1: two types, same peer, plus a self loop
        ("relationship--m1a", "malware--M1", "indicator--I2",
         "communicates-with"),
        ("relationship--m1b", "malware--M1", "indicator--I2", "uses"),
        ("relationship--m1c", "malware--M1", "malware--M1", "uses"),
        # M2: two distinct peers through two different allowed types
        ("relationship--m2a", "malware--M2", "indicator--I7",
         "communicates-with"),
        ("relationship--m2b", "malware--M2", "indicator--I5", "uses"),
    ]
    return entities, edges


def inbound_scenario():
    """Only incoming support exists; an ``in`` alternative must accept it.

    After V (no incoming edge) and Z (one incoming edge) leave in wave 1,
    X, Y and W still each have two distinct incoming indicator peers, so the
    rest is stable.
    """
    entities = [("indicator--X", "indicator"), ("indicator--Y", "indicator"),
                ("indicator--Z", "indicator"), ("indicator--W", "indicator"),
                ("indicator--V", "indicator")]
    edges = [
        ("relationship--e01", "indicator--Y", "indicator--X", "indicates"),
        ("relationship--e02", "indicator--W", "indicator--X", "indicates"),
        ("relationship--e03", "indicator--X", "indicator--Y", "indicates"),
        ("relationship--e04", "indicator--Z", "indicator--Y", "indicates"),
        ("relationship--e05", "indicator--W", "indicator--Y", "indicates"),
        ("relationship--e06", "indicator--X", "indicator--W", "indicates"),
        ("relationship--e07", "indicator--Y", "indicator--W", "indicates"),
        ("relationship--e08", "indicator--X", "indicator--Z", "indicates"),
    ]
    return entities, edges


def same_wave_scenario():
    """Two malware that only support each other, each needing two peers.

    Both fail in the *same* wave, and their connecting relationship records
    both endpoints as leaving in that wave.
    """
    entities = [("malware--Q1", "malware"), ("malware--Q2", "malware")]
    edges = [
        ("relationship--q1", "malware--Q1", "malware--Q2", "uses"),
        ("relationship--q2", "malware--Q2", "malware--Q1", "uses"),
    ]
    return entities, edges


def excluded_scenario():
    """I1 and I2 support each other; I2 also points at the excluded I3.

    I3 leaves in wave 0 with its edge; I4 has only a self loop and fails the
    wave-1 count rule.  I1/I2 survive because their support was never solely
    the rejected record.
    """
    entities = [("indicator--I1", "indicator"),
                ("indicator--I2", "indicator"),
                ("indicator--I3", "indicator"),
                ("indicator--I4", "indicator")]
    edges = [
        ("relationship--e1", "indicator--I1", "indicator--I2", "indicates"),
        ("relationship--e2", "indicator--I2", "indicator--I1", "indicates"),
        ("relationship--e3", "indicator--I2", "indicator--I3", "indicates"),
        ("relationship--e4", "indicator--I4", "indicator--I4", "indicates"),
    ]
    return entities, edges


def empty_scenario():
    """A cycle of two, both failing the wave-1 count requirement: empty load."""
    entities = [("indicator--E1", "indicator"),
                ("indicator--E2", "indicator")]
    edges = [
        ("relationship--r1", "indicator--E1", "indicator--E2", "indicates"),
        ("relationship--r2", "indicator--E2", "indicator--E1", "indicates"),
    ]
    return entities, edges


def scale_scenario(chain_len=60, stable_pairs=200, fanout=500):
    """A long elimination chain, a big unrelated stable partition, a hub.

    ``L0 -> L1 -> ... -> L(n-1)``: the tail has no outgoing peer, so it leaves
    in wave 1 and the chain collapses one link per wave.  Every stable pair
    supports itself with two mutual edges and never loses a peer.  The hub has
    ``fanout`` outgoing peers which all fail in wave 1 at once and no stable
    partner, so it fails in wave 2 after losing that whole neighbour list in
    one indexed step.
    """
    entities, edges = [], []
    for i in range(chain_len):
        entities.append((f"indicator--L{i:05d}", "indicator"))
    for i in range(chain_len - 1):
        edges.append((f"relationship--lc{i:05d}", f"indicator--L{i:05d}",
                      f"indicator--L{i + 1:05d}", "indicates"))
    for i in range(stable_pairs):
        a, b = f"indicator--P{i:06d}a", f"indicator--P{i:06d}b"
        entities += [(a, "indicator"), (b, "indicator")]
        edges += [(f"relationship--pc{i:06d}1", a, b, "indicates"),
                  (f"relationship--pc{i:06d}2", b, a, "indicates")]
    entities.append(("indicator--HUB", "indicator"))
    for j in range(fanout):
        peer = f"indicator--H{j:05d}x"
        entities.append((peer, "indicator"))
        edges.append((f"relationship--hc{j:05d}", "indicator--HUB", peer,
                      "indicates"))
    return entities, edges


SCENARIOS = {
    "main": main_scenario,
    "inbound": inbound_scenario,
    "same_wave": same_wave_scenario,
    "excluded": excluded_scenario,
    "empty": empty_scenario,
}


# ------------------------------------------------------------------ contracts ----

def _alt(aid, direction, types, peers, minimum):
    return {"id": aid, "direction": direction, "relationship_types": list(types),
            "peer_types": list(peers), "min_distinct_peers": minimum}


def contract(doc_id, rel_types, excluded, groups, sets):
    return {"schema": CONTRACT_SCHEMA,
            "relationship_types": list(rel_types),
            "exclude_entity_ids": list(excluded),
            "requirement_groups": groups,
            "named_requirement_sets": sets}


def contract_main(exclude=()):
    """Indicator: >=1 out indicator peer.  Malware: >=2 distinct peers via
    either allowed type (each alternative names both types, so either one
    alone can satisfy the group)."""
    groups = [
        {"id": "G-IND-OUT", "alternatives": [
            _alt("A-IND-OUT", "out", ["indicates"], ["indicator"], 1)]},
        {"id": "G-MAL-OUT", "alternatives": [
            _alt("A-MAL-CW", "out", ["communicates-with"],
                 ["indicator", "malware"], 2),
            _alt("A-MAL-USES", "out", ["uses"],
                 ["indicator", "malware"], 2)]},
    ]
    sets = [{"id": "SET-IND", "entity_type": "indicator",
             "groups": ["G-IND-OUT"]},
            {"id": "SET-MAL", "entity_type": "malware",
             "groups": ["G-MAL-OUT"]}]
    return contract("main", ["indicates", "communicates-with", "uses"],
                    exclude, groups, sets)


def contract_inbound():
    groups = [{"id": "G-IND-IN", "alternatives": [
        _alt("A-IND-IN", "in", ["indicates"], ["indicator"], 2)]}]
    sets = [{"id": "SET-IND", "entity_type": "indicator",
             "groups": ["G-IND-IN"]}]
    return contract("inbound", ["indicates"], [], groups, sets)


def contract_same_wave():
    groups = [{"id": "G-MAL", "alternatives": [
        _alt("A-MAL", "out", ["uses"], ["malware"], 2)]}]
    sets = [{"id": "SET-MAL", "entity_type": "malware", "groups": ["G-MAL"]}]
    return contract("same-wave", ["uses"], [], groups, sets)


def contract_excluded(exclude=("indicator--I3",)):
    groups = [{"id": "G-IND", "alternatives": [
        _alt("A-IND", "out", ["indicates"], ["indicator"], 1)]}]
    sets = [{"id": "SET-IND", "entity_type": "indicator",
             "groups": ["G-IND"]}]
    return contract("excluded", ["indicates"], exclude, groups, sets)


def contract_empty():
    groups = [{"id": "G-IND", "alternatives": [
        _alt("A-IND", "out", ["indicates"], ["indicator"], 3)]}]
    sets = [{"id": "SET-IND", "entity_type": "indicator",
             "groups": ["G-IND"]}]
    return contract("empty", ["indicates"], [], groups, sets)


def contract_scale():
    """Chain: >=1 out indicator peer.  Stable pairs: >=1 out, which mutual
    edges satisfy.  HUB: >=2 out, satisfied only while some peers are live."""
    groups = [{"id": "G-IND", "alternatives": [
        _alt("A-IND", "out", ["indicates"], ["indicator"], 1)]}]
    sets = [{"id": "SET-IND", "entity_type": "indicator",
             "groups": ["G-IND"]}]
    return contract("scale", ["indicates"], [], groups, sets)


def write_batch(path, doc):
    with open(path, "wb") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output")
    ap.add_argument("--scenario", default="main")
    ap.add_argument("--chain", type=int, default=60)
    ap.add_argument("--stable-pairs", type=int, default=200)
    ap.add_argument("--fanout", type=int, default=500)
    args = ap.parse_args()
    if args.scenario == "scale":
        entities, edges = scale_scenario(args.chain, args.stable_pairs,
                                         args.fanout)
    else:
        entities, edges = SCENARIOS[args.scenario]()
    write_projection(args.output, entities, edges)
    print(json.dumps({"entities": len(entities), "edges": len(edges)}))


if __name__ == "__main__":
    main()
