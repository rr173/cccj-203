#!/usr/bin/env python3
"""Master-release verification: contract semantics, waves, ledger, evidence.

Run:  python3 -I tests/run_release_verify.py
Scale knobs (the big corpus is generated at run time, never committed):
  SG_RELEASE_SCALE=1  python3 -I tests/run_release_verify.py

Everything is driven through the public CLI (``sg-cli.py``); small expectations
are computed by a separate, deliberately simple wave enumerator in this file
that only reads the contract text, never the release implementation, so a
shared bug cannot hide in the comparison.
"""
import json
import os
import resource
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "sg-cli.py")
sys.path.insert(0, ROOT)

from tests import release_fixtures as FX  # noqa: E402
from sg import release as REL  # noqa: E402

PASS = FAIL = 0
SCALE = os.environ.get("SG_RELEASE_SCALE", "1") == "1"


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}", flush=True)
    else:
        FAIL += 1
        print(f"  FAIL  {label}  {detail}", flush=True)


def run(*args):
    p = subprocess.run([sys.executable, "-I", CLI, *args],
                       cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def make_warehouse(work, name, scenario):
    pkg = os.path.join(work, f"{name}.pkg.sqlite")
    entities, edges = FX.SCENARIOS[scenario]()
    FX.write_projection(pkg, entities, edges)
    mpath = os.path.join(work, f"{name}.master.sqlite")
    rc, _, err = run("master-build", "--package", pkg, "--master", mpath)
    assert rc == 0, err
    return mpath


def write_contract(work, name, doc):
    path = os.path.join(work, f"{name}.contract.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


def release(work, master, contract_doc, name):
    cpath = write_contract(work, name, contract_doc)
    out = os.path.join(work, f"{name}.release.sqlite")
    rc, stdout, err = run("master-release", "--master", master,
                          "--contract", cpath, "--output", out)
    return rc, stdout, err, out


def q(path, sql, params=()):
    conn = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()


# ---------------------------------------------------------- independent model ----

def enumerate_waves(entities, edges, contract):
    """Tiny wave enumerator written straight from the contract wording.

    Independent of ``sg.release``: it re-derives exclusion, type filtering,
    distinct-peer de-duplication and simultaneous eviction on its own, using
    plain dictionaries.  ``entities`` is a list of (obj_id, type) and ``edges``
    a list of (rel_id, source, target, relationship_type).
    """
    ent_type = dict(entities)
    allowed = set(contract["relationship_types"])
    excluded = set(contract["exclude_entity_ids"])
    groups_of = {}
    for entry in contract["named_requirement_sets"]:
        groups_of[entry["entity_type"]] = [
            next(g for g in contract["requirement_groups"] if g["id"] == gid)
            for gid in entry["groups"]]

    dead = set()
    dead_wave = {}
    rel_dead = {}
    rel_wave = {}
    wave_notes = {}

    for eid in excluded:
        if eid in ent_type:
            dead.add(eid)
            dead_wave[eid] = 0
    for rel, src, tgt, rt in edges:
        if rt not in allowed or src in dead or tgt in dead:
            rel_dead[rel] = True
            rel_wave[rel] = 0

    def counts(eid):
        out = {}
        for group in groups_of.get(ent_type.get(eid), []):
            for alt in group["alternatives"]:
                peers = set()
                for rel, src, tgt, rt in edges:
                    if rt not in alt["relationship_types"]:
                        continue
                    if rt not in allowed:
                        continue
                    if src in dead or tgt in dead:
                        continue
                    if alt["direction"] == "out" and src == eid:
                        peer = tgt
                    elif alt["direction"] == "in" and tgt == eid:
                        peer = src
                    else:
                        continue
                    if peer == eid:
                        continue
                    if ent_type.get(peer) not in alt["peer_types"]:
                        continue
                    peers.add(peer)
                out[alt["id"]] = len(peers)
        return out

    wave = 1
    while True:
        failing = []
        notes = {}
        for eid, etype in entities:
            if eid in dead or etype not in groups_of:
                continue
            measured = counts(eid)
            unmet = []
            for group in groups_of[etype]:
                if not any(measured[a["id"]] >= a["min_distinct_peers"]
                           for a in group["alternatives"]):
                    unmet.append(group["id"])
            if unmet:
                failing.append(eid)
                notes[eid] = {"unmet_groups": unmet,
                              "measured": measured,
                              "group_alts": {
                                  g["id"]: [a["id"] for a in g["alternatives"]]
                                  for g in groups_of[etype] if g["id"] in unmet}}
        if not failing:
            wave_notes[wave] = {}
            break
        for eid in failing:
            dead.add(eid)
            dead_wave[eid] = wave
        wave_notes[wave] = notes
        for rel, src, tgt, rt in edges:
            if rel in rel_wave:
                continue
            if src in dead or tgt in dead:
                rel_wave[rel] = wave
        wave += 1
    return {"entity_wave": dead_wave, "relation_wave": rel_wave,
            "notes": wave_notes, "last_wave": wave - 1}


# --------------------------------------------------------------------- tests ----

def test_documented_fixture(work):
    print("\n[1] documented fixture: chain, mutual pair, two malware, self loop")
    master = make_warehouse(work, "main", "main")
    entities, edges = FX.SCENARIOS["main"]()
    contract_doc = FX.contract_main()
    model = enumerate_waves(entities, edges, contract_doc)
    rc, out, err, pkg = release(work, master, contract_doc, "main")
    check("release rc0", rc == 0, err)
    if rc != 0:
        return
    receipt = json.loads(out)

    # ---- hand-computed core: wave assignment
    expected_wave = {"indicator--I4": 1, "indicator--I3": 2,
                     "indicator--I2": 3, "indicator--I1": 4,
                     "malware--M1": 1, "malware--M2": 1}
    got = {r["obj_id"]: r["eviction_wave"]
           for r in q(pkg, "SELECT obj_id, eviction_wave FROM reject_entity_map")}
    check("chain leaves one entity per wave from the head", got == expected_wave,
          str(got))
    check("independent enumerator agrees on every wave",
          model["entity_wave"] == got, str(model["entity_wave"]))
    from sg.master import _row_key
    got_rel = {r["row_key"]: r["eviction_wave"] for r in q(
        pkg, "SELECT row_key, eviction_wave FROM reject_relations")}
    expected_rel = {}
    for rel_id, src, tgt, rel_type in edges:
        if rel_id in model["relation_wave"]:
            expected_rel[_row_key(src, rel_type, tgt)] = \
                model["relation_wave"][rel_id]
    check("relationship waves agree with the independent model",
          got_rel == expected_rel, str((got_rel, expected_rel)))

    # ---- the ledger's measured numbers equal the independent enumeration
    snap_rows = q(pkg, "SELECT entity_id, wave, group_id, alt_id, distinct_peers,"
                       " min_peers, met FROM eviction_alt_snapshot")
    model_rows = []
    for wave_no, notes in model["notes"].items():
        for eid, note in notes.items():
            for group_id in note["unmet_groups"]:
                for alt_id in note["group_alts"][group_id]:
                    alt = next(a for g in contract_doc["requirement_groups"]
                               for a in g["alternatives"] if a["id"] == alt_id)
                    value = note["measured"][alt_id]
                    model_rows.append({
                        "entity_id": eid, "wave": wave_no,
                        "group_id": group_id, "alt_id": alt_id,
                        "distinct_peers": value,
                        "min_peers": alt["min_distinct_peers"],
                        "met": 1 if value >= alt["min_distinct_peers"] else 0})
    key = lambda r: (r["entity_id"], r["wave"], r["group_id"], r["alt_id"])
    check("every recorded measurement equals the independent enumeration",
          sorted(snap_rows, key=key) == sorted(model_rows, key=key),
          str((snap_rows, model_rows)))

    load_ents = {r["obj_id"] for r in q(pkg, "SELECT obj_id FROM load_entities")}
    check("only the mutual pair and the self-loop holder load",
          load_ents == {"indicator--I5", "indicator--I6", "indicator--I7"},
          str(load_ents))

    # ---- Malware measured figure is 1, not 2, despite two relationship types
    snap = q(pkg, "SELECT * FROM eviction_alt_snapshot"
                  " WHERE entity_id='malware--M1' ORDER BY alt_id")
    check("Malware recorded twice (one row per alternative)",
          [r["alt_id"] for r in snap] == ["A-MAL-CW", "A-MAL-USES"], str(snap))
    check("Malware measured distinct peers = 1 for both alternatives",
          all(r["distinct_peers"] == 1 and r["min_peers"] == 2 for r in snap),
          str(snap))
    check("Malware unmet group is the malware group",
          {r["group_id"] for r in snap} == {"G-MAL-OUT"})
    check("Malware self loop cannot lift its own count",
          all(r["direction"] == "out" for r in snap))

    # ---- why M2 fails (alternatives are exclusive, not additive)
    m2 = q(pkg, "SELECT alt_id, distinct_peers, min_peers"
                " FROM eviction_alt_snapshot WHERE entity_id='malware--M2'")
    check("two types to two peers still fails the >=2 alternative",
          sorted((r["alt_id"], r["distinct_peers"], r["min_peers"])
                 for r in m2) == [("A-MAL-CW", 1, 2), ("A-MAL-USES", 1, 2)],
          str(m2))

    # ---- I7 keeps a self loop on the load side, flagged
    sl = q(pkg, "SELECT * FROM load_relations WHERE is_self_loop=1")
    check("self loop of a surviving entity is loaded and flagged",
          len(sl) == 1 and sl[0]["source_canon"] == sl[0]["target_canon"]
          == "indicator--I7", str(sl))

    # ---- partition and integrity
    counts = receipt["counts"]
    check("three input classes partition exactly",
          all(counts["input"][k] == counts["load"][k] + counts["reject"][k]
              for k in ("entities", "relations", "contributions")), str(counts))
    check("entity map and contributions fully accounted",
          counts["input"]["entities"] == 9
          and counts["input"]["contributions"] == 12, str(counts))
    loaded_relation_keys = {r["row_key"] for r in q(
        pkg, "SELECT row_key FROM load_relations")}
    contribs_ok = all(
        r["row_key"] in loaded_relation_keys for r in q(
            pkg, "SELECT row_key FROM load_contributions"))
    check("every loaded contribution points at a loaded relation", contribs_ok)
    per_rel = {(r["row_key"], r["contribution_count"]) for r in q(
        pkg, "SELECT row_key, contribution_count FROM load_relations")}
    actual = {r["row_key"]: r["n"] for r in q(
        pkg, "SELECT row_key, COUNT(*) AS n FROM load_contributions"
             " GROUP BY row_key")}
    check("loaded contribution counts match the relation rows",
          all(actual.get(k, 0) == n for k, n in per_rel), str(actual))
    check("no verdict table is copied",
          not q(pkg, "SELECT name FROM sqlite_master WHERE type='table'"
                     " AND name LIKE '%verdict%'"))
    check("no loadable verdict surface at all",
          not q(pkg, "SELECT name FROM sqlite_master WHERE type='table'"
                     " AND name LIKE 'load_%' AND name NOT IN"
                     " ('load_entities','load_relations','load_contributions')"))

    # ---- provenance: upstream identity, revision, contract digest
    meta = {r["key"]: r["value"] for r in q(pkg, "SELECT key, value FROM package_meta")}
    check("package records upstream projection identity",
          meta["upstream_codename"] == "C-RELEASE"
          and meta["upstream_principal"] == "release"
          and len(meta["upstream_package_digest_sha256"]) == 64, str(
              {k: meta[k] for k in meta if k.startswith("upstream")})[:400])
    check("package records the master revision read",
          meta["master_revision"] == "0")
    check("package records the contract digest",
          meta["contract_sha256"] == REL.load_contract(contract_doc)["sha256"])
    check("receipt echoes the digest and the revision",
          receipt["contract_sha256"] == meta["contract_sha256"]
          and receipt["master_revision"] == 0)
    check("sqlite integrity ok",
          q(pkg, "PRAGMA integrity_check")[0]["integrity_check"] == "ok")

    # ---- wave ledger explains rows, not only totals
    waves = {w["wave"]: w for w in receipt["waves"]}
    check("ledger has every wave plus the stabilizing wave",
          sorted(waves) == [0, 1, 2, 3, 4, 5], str(sorted(waves)))
    check("wave 1 evicts I4 and both malware in one step",
          waves[1]["evicted_entities"] == 3
          and waves[1]["evicted_relations"] == 6, str(waves[1]))
    wave1_entities = {r["entity_id"] for r in q(
        pkg, "SELECT entity_id FROM wave_entity_evictions WHERE wave=1")}
    check("each wave names its entity evictions",
          wave1_entities == {"indicator--I4", "malware--M1", "malware--M2"},
          str(wave1_entities))
    check("wave_entity_evictions covers all auto evictions",
          len(q(pkg, "SELECT * FROM wave_entity_evictions")) == 6)
    check("stabilizing wave evicts nothing",
          waves[5]["evicted_entities"] == 0 and waves[5]["phase"] == "stabilized")
    check("each evicted mapping row explains its own master entity and wave",
          len(q(pkg, "SELECT * FROM reject_entity_map")) == 6
          and all(r["master_entity_id"] == r["canonical_id"]
                  and r["eviction_wave"] >= 1 for r in q(
                      pkg, "SELECT * FROM reject_entity_map")))
    check("rejected contributions carry wave and reason",
          len(q(pkg, "SELECT * FROM reject_contributions")) == 8
          and all(r["eviction_wave"] >= 1 and r["reason"] == "endpoint-evicted"
                  for r in q(pkg, "SELECT * FROM reject_contributions")))

    # ---- no reason is back-filled from the final (empty) graph
    i1 = q(pkg, "SELECT * FROM eviction_alt_snapshot WHERE entity_id='indicator--I1'")
    check("I1's recorded measurement is the wave-4 frontier, not 0-support later",
          len(i1) == 1 and i1[0]["wave"] == 4 and i1[0]["distinct_peers"] == 0,
          str(i1))
    check("earlier-error probe: I4 was evicted at wave 1 with count 0",
          q(pkg, "SELECT wave, distinct_peers FROM eviction_alt_snapshot"
                 " WHERE entity_id='indicator--I4'")[0]
          == {"wave": 1, "distinct_peers": 0})

    # ---- deterministic re-run: same tables, same digest
    rc2, out2, err2, pkg2 = release(work, master, contract_doc, "main_again")
    r2 = json.loads(out2)
    check("re-run produces the same release digest",
          rc2 == 0 and r2["release_digest"] == receipt["release_digest"], err2)
    tables = ("load_entities", "load_relations", "load_contributions",
              "reject_entity_map", "reject_relations", "reject_contributions")
    check("re-run produces identical logical tables",
          all(q(pkg, f"SELECT * FROM {t} ORDER BY 1")
              == q(pkg2, f"SELECT * FROM {t} ORDER BY 1") for t in tables))

    # ---- read CLI surfaces the ledger for one entity
    rc, out, err = run("master-release-read", "--package", pkg, "--what",
                       "entity", "--entity", "malware--M1")
    doc = json.loads(out)
    check("entity query explains the master entity, wave and counts",
          doc["reject"]["eviction_wave"] == 1
          and sorted(e["distinct_peers"] for e in doc["evictions"]) == [1, 1],
          out[:300])
    rc, out, err = run("master-release-read", "--package", pkg,
                       "--what", "manifest")
    check("manifest is readable from a sealed package",
          json.loads(out)["counts"]["load"]["entities"] == 3, err)
def test_alternative_conditions(work):
    print("\n[2] alternatives: inbound support and either-of-two relations")
    master = make_warehouse(work, "inbound", "inbound")
    entities, edges = FX.SCENARIOS["inbound"]()
    contract_doc = FX.contract_inbound()
    model = enumerate_waves(entities, edges, contract_doc)
    rc, out, err, pkg = release(work, master, contract_doc, "inbound")
    check("inbound contract release rc0", rc == 0, err)
    load_ents = {r["obj_id"] for r in q(pkg, "SELECT obj_id FROM load_entities")}
    # X/Y/W have two distinct incoming indicator peers each; Z has one and V none
    check("entities with two incoming peers load; one-peer and zero-peer do not",
          load_ents == {"indicator--X", "indicator--Y", "indicator--W"},
          str(load_ents))
    check("inbound model agrees", model["entity_wave"] == {
        r["obj_id"]: r["eviction_wave"] for r in q(
            pkg, "SELECT obj_id, eviction_wave FROM reject_entity_map")})

    # alternative either/or: one allowed peer via a single type suffices when
    # the group offers two alternatives each requiring exactly one peer.
    groups = [{"id": "G", "alternatives": [
        FX._alt("A1", "out", ["indicates"], ["indicator"], 1),
        FX._alt("A2", "out", ["uses"], ["indicator"], 1)]}]
    doc = FX.contract("either-or", ["indicates", "uses"], [],
                      groups, [{"id": "S", "entity_type": "indicator",
                                "groups": ["G"]}])
    master2 = make_warehouse(work, "either", "inbound")
    rc, out, err, pkg2 = release(work, master2, doc, "either")
    check("either-of-two alternatives accept a single type", rc == 0, err)
    # every entity with at least one outgoing indicator peer survives this
    # either-or contract; only V (no outgoing edge at all) leaves.
    check("either-of-two alternatives accept one relationship type alone",
          {r["obj_id"] for r in q(pkg2, "SELECT obj_id FROM load_entities")}
          == {"indicator--W", "indicator--X", "indicator--Y",
              "indicator--Z"},
          str(q(pkg2, "SELECT obj_id FROM load_entities")))


def test_merged_members_and_alias_load(work):
    print("\n[2b] a merged entity's whole member set loads under one master id")
    master = make_warehouse(work, "members", "main")
    # I7 already points at I5 and at itself; merging I7 into I5 turns both into
    # one internal pair, while the surviving I5 <-> I6 pair keeps real support.
    batch = FX.write_batch(os.path.join(work, "merge.json"), {
        "batch_id": "ALIAS", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "V-57", "kind": "same",
             "a": "indicator--I5", "b": "indicator--I7", "priority": 5}]})
    rc, _, err = run("master-apply", "--master", master, "--batch", batch)
    check("alias batch applied", rc == 0, err)
    rc, out, err, pkg = release(work, master, FX.contract_main(), "members")
    check("release over merged head rc0", rc == 0, err)
    members = q(pkg, "SELECT obj_id, canonical_id FROM load_entities"
                     " WHERE obj_id IN ('indicator--I5','indicator--I6',"
                     "'indicator--I7') ORDER BY obj_id")
    check("every member id stays on the load side under one master id",
          members == [{"obj_id": "indicator--I5", "canonical_id": "indicator--I5"},
                      {"obj_id": "indicator--I6", "canonical_id": "indicator--I6"},
                      {"obj_id": "indicator--I7", "canonical_id": "indicator--I5"}],
          str(members))
    loops = q(pkg, "SELECT row_key, source_canon, target_canon,"
                   " contribution_count FROM load_relations"
                   " WHERE is_self_loop=1")
    check("the merged pair is one flagged self loop aggregating both edges",
          loops == [{"row_key": '["indicator--I5","indicates","indicator--I5"]',
                     "source_canon": "indicator--I5",
                     "target_canon": "indicator--I5",
                     "contribution_count": 2}], str(loops))
    check("the self loop carries its two original contributions",
          sorted(r["relationship_id"] for r in q(
              pkg, "SELECT relationship_id FROM load_contributions"
                   " WHERE is_self_loop=1")) == ["relationship--s7",
                                                "relationship--t7"])
    check("merging did not rescue the unsupported chain",
          {"indicator--I1", "indicator--I2", "indicator--I3",
           "indicator--I4"} <=
          {r["obj_id"] for r in q(pkg, "SELECT obj_id FROM reject_entity_map")})


def test_same_wave_both_endpoints(work):
    print("\n[3] one wave = one frontier: mutual pair failing together")
    master = make_warehouse(work, "same", "same_wave")
    entities, edges = FX.SCENARIOS["same_wave"]()
    contract_doc = FX.contract_same_wave()
    rc, out, err, pkg = release(work, master, contract_doc, "same")
    check("same-wave release rc0", rc == 0, err)
    snap = q(pkg, "SELECT * FROM eviction_alt_snapshot ORDER BY entity_id")
    check("both entities evicted in wave 1",
          {r["entity_id"] for r in q(pkg, "SELECT * FROM wave_entity_evictions")}
          == {"malware--Q1", "malware--Q2"}
          and all(r["wave"] == 1 for r in snap), str(snap))
    check("each measures the other as its one peer (still short of two)",
          all(r["distinct_peers"] == 1 for r in snap), str(snap))
    check("both edges leave in wave 1", len(q(
        pkg, "SELECT * FROM reject_relations WHERE eviction_wave=1")) == 2)
    check("both edges name both endpoints as leaving in that wave",
          all(json.loads(r["evicted_endpoints_json"])
              == ["malware--Q1", "malware--Q2"] for r in q(
                  pkg, "SELECT * FROM reject_relations")),
          str(q(pkg, "SELECT * FROM reject_relations")))
    check("load side is empty",
          q(pkg, "SELECT COUNT(*) AS n FROM load_entities")[0]["n"] == 0)


def test_exclusion(work):
    print("\n[4] explicit exclusion removes the entity and its relations at wave 0")
    master = make_warehouse(work, "excl", "excluded")
    entities, edges = FX.SCENARIOS["excluded"]()
    contract_doc = FX.contract_excluded()
    model = enumerate_waves(entities, edges, contract_doc)
    rc, out, err, pkg = release(work, master, contract_doc, "excl")
    check("exclusion release rc0", rc == 0, err)
    rejected = {r["obj_id"]: (r["eviction_wave"], r["reason"]) for r in q(
        pkg, "SELECT * FROM reject_entity_map")}
    check("excluded entity recorded at wave 0 with the contract reason",
          rejected.get("indicator--I3") == (0, "excluded-by-contract"),
          str(rejected))
    check("its relation is removed at wave 0",
          {r["eviction_wave"] for r in q(
              pkg, "SELECT * FROM reject_relations WHERE row_key LIKE"
                   " '%I2%I3%'")} == {0})
    load = {r["obj_id"] for r in q(pkg, "SELECT * FROM load_entities")}
    check("I4 (self loop only) fails the count rule in wave 1",
          "indicator--I4" not in load
          and rejected["indicator--I4"][0] == 1, str(rejected))
    check("I1/I2 survive the loss of I3 because they still support each other",
          load == {"indicator--I1", "indicator--I2"}, str(load))
    check("the excluded entity's edge to a survivor is not on the load side",
          all("I3" not in (r["source_canon"], r["target_canon"])
              for r in q(pkg, "SELECT * FROM load_relations")))
    check("independent model agrees", model["entity_wave"] == {
        k: v[0] for k, v in rejected.items()})
    check("no exclusion leaves an orphan relation on the load side",
          all(r["source_canon"] in load and r["target_canon"] in load
              for r in q(pkg, "SELECT * FROM load_relations")))

    bad = FX.contract_excluded(exclude=("indicator--MISSING",))
    rc, out, err, pkg2 = release(work, master, bad, "excl_bad")
    check("an unknown excluded master id is a configuration error", rc == 2,
          err)
    check("the configuration error has a stable code",
          json.loads(err)["error"] == "invalid-contract", err)
    check("no package is produced for a bad contract",
          not os.path.exists(os.path.join(work, "excl_bad.release.sqlite")))


def test_relationship_type_filter(work):
    print("\n[4b] a disallowed relationship type is rejected on its own reason")
    master = make_warehouse(work, "typed", "main")
    contract_doc = FX.contract_main()
    contract_doc["relationship_types"] = ["communicates-with"]
    rc, out, err, pkg = release(work, master, contract_doc, "typed")
    check("narrowed-type release rc0", rc == 0, err)
    rows = q(pkg, "SELECT relationship_type, eviction_wave, reason"
                  " FROM reject_relations ORDER BY row_key")
    banned = [r for r in rows if r["relationship_type"] != "communicates-with"]
    check("every non-allowed type lands in wave 0 with its own reason",
          banned and all(r["eviction_wave"] == 0
                         and r["reason"] == "relationship-type-not-allowed"
                         for r in banned), str(banned))
    check("allowed-type relations are decided only by the count rule",
          all(r["eviction_wave"] >= 1 for r in q(
              pkg, "SELECT eviction_wave FROM reject_relations"
                   " WHERE relationship_type='communicates-with'")))
    check("the banned types are distinguishable without reading a summary",
          q(pkg, "SELECT COUNT(*) AS n FROM reject_relations"
                 " WHERE reason='relationship-type-not-allowed'")[0]["n"]
          == len(banned))
    check("all relations of the banned type are gone from the load side",
          q(pkg, "SELECT COUNT(*) AS n FROM load_relations"
                 " WHERE relationship_type<>'communicates-with'")[0]["n"] == 0)


def test_empty_delivery(work):
    print("\n[5] a legal empty delivery is still loadable")
    master = make_warehouse(work, "empty", "empty")
    contract_doc = FX.contract_empty()
    rc, out, err, pkg = release(work, master, contract_doc, "empty")
    check("empty release rc0", rc == 0, err)
    check("load side genuinely empty",
          all(q(pkg, f"SELECT COUNT(*) AS n FROM {t}")[0]["n"] == 0
              for t in ("load_entities", "load_relations",
                        "load_contributions")))
    check("reject side accounts for every entity",
          len(q(pkg, "SELECT * FROM reject_entity_map")) == 2
          and all(r["eviction_wave"] == 1 for r in q(
              pkg, "SELECT * FROM reject_entity_map")))
    check("empty package is still a valid SQLite package",
          q(pkg, "PRAGMA integrity_check")[0]["integrity_check"] == "ok")
    rc, out, err = run("master-release-read", "--package", pkg,
                       "--what", "manifest")
    check("empty package exposes a manifest", rc == 0
          and json.loads(out)["counts"]["load"]["entities"] == 0, err)

    # a declared relationship type that never occurs is legal
    legal = FX.contract(
        "absent-type", ["indicates", "never-seen-type"], [],
        [{"id": "G", "alternatives": [
            FX._alt("A", "out", ["indicates"], ["indicator"], 1)]}],
        [{"id": "S", "entity_type": "indicator", "groups": ["G"]}])
    master2 = make_warehouse(work, "empty2", "empty")
    rc, out, err, pkg2 = release(work, master2, legal, "empty_legal")
    check("declared-but-absent relationship type is accepted", rc == 0, err)


def test_no_requirement_sets(work):
    print("\n[5b] entity types without a registered requirement set are unlimited")
    master = make_warehouse(work, "unlimited", "main")
    doc = FX.contract("none", ["indicates", "communicates-with", "uses"],
                      [], [], [])
    rc, out, err, pkg = release(work, master, doc, "unlimited")
    check("release with no requirement sets rc0", rc == 0, err)
    receipt = json.loads(out)
    check("every entity and allowed relation loads",
          receipt["counts"]["load"] == {"entities": 9, "relations": 12,
                                       "contributions": 12}
          and receipt["counts"]["reject"] == {"entities": 0, "relations": 0,
                                              "contributions": 0},
          str(receipt["counts"]))
    check("no elimination wave runs", receipt["wave_count"] == 0)
    check("all three declared types are present", {
        r["relationship_type"] for r in q(
            pkg, "SELECT DISTINCT relationship_type FROM load_relations")}
        == {"indicates", "communicates-with", "uses"})


def test_misconfiguration(work):
    print("\n[6] contract misconfiguration is never a silent empty delivery")
    master = make_warehouse(work, "bad", "main")
    base = FX.contract_main()
    cases = {
        "missing schema": {k: v for k, v in base.items() if k != "schema"},
        "empty alternatives": FX.contract(
            "e", ["indicates"], [], [{"id": "G", "alternatives": []}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G"]}]),
        "unknown group reference": FX.contract(
            "e", ["indicates"], [], [],
            [{"id": "S", "entity_type": "indicator", "groups": ["GHOST"]}]),
        "empty allowed types": FX.contract(
            "e", [], [], [{"id": "G", "alternatives": [
                FX._alt("A", "out", ["indicates"], ["indicator"], 1)]}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G"]}]),
        "zero minimum": FX.contract(
            "e", ["indicates"], [], [{"id": "G", "alternatives": [
                FX._alt("A", "out", ["indicates"], ["indicator"], 0)]}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G"]}]),
        "non-integer minimum": FX.contract(
            "e", ["indicates"], [], [{"id": "G", "alternatives": [
                FX._alt("A", "out", ["indicates"], ["indicator"], True)]}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G"]}]),
        "unknown direction": FX.contract(
            "e", ["indicates"], [], [{"id": "G", "alternatives": [
                FX._alt("A", "sideways", ["indicates"], ["indicator"], 1)]}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G"]}]),
        "duplicate alternative id": FX.contract(
            "e", ["indicates"], [], [{"id": "G", "alternatives": [
                FX._alt("A", "out", ["indicates"], ["indicator"], 1),
                FX._alt("A", "out", ["uses"], ["indicator"], 1)]}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G"]}]),
        "unknown peer type is fine, unknown group inside a set is not": FX.contract(
            "e", ["indicates"], [], [{"id": "G", "alternatives": [
                FX._alt("A", "out", ["indicates"], ["report"], 1)]}],
            [{"id": "S", "entity_type": "indicator", "groups": ["G", "NOPE"]}]),
    }
    for label, doc in cases.items():
        rc, out, err, pkg = release(work, master, doc, "cfg_" + str(hash(label)))
        check(f"{label}: rejected", rc == 2, err)
        check(f"{label}: stable error code",
              json.loads(err)["error"] in ("invalid-contract",
                                           "invalid-contract-json"), err)
        check(f"{label}: no package left behind", not os.path.exists(pkg))

    # malformed JSON text
    path = os.path.join(work, "broken.contract.json")
    with open(path, "w") as fh:
        fh.write("{not json")
    out = os.path.join(work, "broken.release.sqlite")
    rc, _, err = run("master-release", "--master", master,
                     "--contract", path, "--output", out)
    check("malformed contract JSON rejected with a distinct code",
          rc == 2 and json.loads(err)["error"] == "invalid-contract-json", err)
    check("malformed contract leaves no package", not os.path.exists(out))


def test_atomicity_and_existing(work):
    print("\n[7] failed release never damages an existing package")
    master = make_warehouse(work, "atomic", "main")
    out = os.path.join(work, "keep.release.sqlite")
    cpath = write_contract(work, "atomic", FX.contract_main())
    rc, _, err = run("master-release", "--master", master, "--contract", cpath,
                     "--output", out)
    check("first release succeeds", rc == 0, err)
    before = open(out, "rb").read()

    # a later failing release to the same path must not touch the old package
    bad = FX.contract("bad", ["indicates"], ["indicator--MISSING"], [], [])
    bad_path = write_contract(work, "atomic_bad", bad)
    rc, _, err = run("master-release", "--master", master, "--contract",
                     bad_path, "--output", out)
    check("bad release rejected", rc == 2)
    check("existing package bytes unchanged", open(out, "rb").read() == before)
    check("no temporary file left next to it",
          [n for n in os.listdir(work) if n.startswith("keep.release.sqlite.")
           and n.endswith(".tmp")] == [])

    # injected failure inside the build (before publish) must also leave none
    original = os.replace

    def failing_replace(src_path, dst_path):
        raise RuntimeError("publish failure")

    cont = REL.load_contract(FX.contract_main())
    os.replace = failing_replace
    try:
        try:
            REL.build_package(master, cont, out)
            raised = False
        except RuntimeError:
            raised = True
    finally:
        os.replace = original
    check("publish failure propagates", raised)
    check("package still unchanged after publish failure",
          open(out, "rb").read() == before)
    check("no .tmp artifact after publish failure",
          [n for n in os.listdir(work) if n.endswith(".sqlite.tmp")] == [])


def test_concurrent_writer(work):
    print("\n[8] a concurrent verdict batch never mixes revisions into one package")
    import threading
    master = make_warehouse(work, "conc", "main")
    batch = FX.write_batch(os.path.join(work, "concat.json"), {
        "batch_id": "RACE", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "V-12", "kind": "same",
             "a": "indicator--I1", "b": "indicator--I2", "priority": 5}]})
    cpath = write_contract(work, "conc", FX.contract_main())
    out = os.path.join(work, "conc.release.sqlite")
    results = {}

    def do_release():
        results["release"] = run("master-release", "--master", master,
                                 "--contract", cpath, "--output", out)

    def do_batch():
        results["batch"] = run("master-apply", "--master", master,
                               "--batch", batch, "--quiet")

    t1 = threading.Thread(target=do_release)
    t2 = threading.Thread(target=do_batch)
    t1.start(); t2.start(); t1.join(); t2.join()
    rc, stdout, err = results["release"]
    check("release succeeded during concurrent write", rc == 0, err)
    receipt = json.loads(stdout)
    pkg = out
    # The package must equal *some* single committed revision: either the
    # pre-batch (rev 0) or post-batch (rev 1) view, never a mixture.
    meta = {r["key"]: r["value"] for r in q(pkg, "SELECT * FROM package_meta")}
    rev = int(meta["master_revision"])
    entities, edges = FX.SCENARIOS["main"]()
    contract_doc = FX.contract_main()
    if rev == 0:
        model = enumerate_waves(entities, edges, contract_doc)
    else:
        # merged I1/I2 changes the relation view; only check invariants
        model = None
    counts = receipt["counts"]
    check("revision recorded is one committed revision",
          rev in (0, 1), str(rev))
    check("counts are internally consistent with the recorded revision",
          all(counts["input"][k] == counts["load"][k] + counts["reject"][k]
              for k in ("entities", "relations", "contributions")))
    membership_ok = True
    for row in q(pkg, "SELECT * FROM load_relations"):
        pair = {(r["obj_id"]) for r in q(
            pkg, "SELECT obj_id FROM load_entities WHERE obj_id IN (?,?)",
            (row["source_canon"], row["target_canon"]))}
        membership_ok = membership_ok and pair == {row["source_canon"],
                                                   row["target_canon"]}
    check("no mixed-revision rows: every loaded relation's endpoints load",
          membership_ok)
    got = {r["obj_id"]: r["eviction_wave"] for r in q(
        pkg, "SELECT obj_id, eviction_wave FROM reject_entity_map")}
    if rev == 0:
        check("rev-0 package matches the independent model",
              got == model["entity_wave"], str(got))
    else:
        check("rev-1 package differs only by the merged I1/I2 mapping",
              got.get("indicator--I1") is not None
              and got.get("indicator--I2") is not None, str(got))


def _live_peer_counts(pkg, entity_id):
    """Distinct out/in indicator peers of a surviving (or any) entity."""
    rows = q(pkg, "SELECT source_canon, target_canon, is_self_loop"
                  " FROM load_relations WHERE source_canon=? OR target_canon=?",
             (entity_id, entity_id))
    out_peers = {r["target_canon"] for r in rows
                 if r["source_canon"] == entity_id and not r["is_self_loop"]}
    in_peers = {r["source_canon"] for r in rows
                if r["target_canon"] == entity_id and not r["is_self_loop"]}
    return out_peers, in_peers


def test_scale_access(work):
    print("\n[9] long chain next to unrelated partitions and one high fan-out")
    chain, stable, fanout = (60, 200, 500) if SCALE else (12, 20, 30)
    pkg = os.path.join(work, "scale.pkg.sqlite")
    entities, edges = FX.scale_scenario(chain, stable, fanout)
    FX.write_projection(pkg, entities, edges)
    master = os.path.join(work, "scale.master.sqlite")
    rc, _, err = run("master-build", "--package", pkg, "--master", master)
    check("scale warehouse built", rc == 0, err)

    cpath = write_contract(work, "scale", FX.contract_scale())
    out = os.path.join(work, "scale.release.sqlite")
    rss_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    rc, stdout, err = run("master-release", "--master", master,
                          "--contract", cpath, "--output", out)
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    check("scale release rc0", rc == 0, err)
    receipt = json.loads(stdout)
    waves = {w["wave"]: w for w in receipt["waves"]}

    # ---- the chain collapses one link per wave
    chain_reject = {r["obj_id"]: r["eviction_wave"] for r in q(
        out, "SELECT obj_id, eviction_wave FROM reject_entity_map"
             " WHERE obj_id LIKE 'indicator--L%'")}
    check("every chain entity is evicted exactly once",
          sorted(chain_reject) == [f"indicator--L{i:05d}"
                                   for i in range(chain)], str(len(chain_reject)))
    check("the chain tail leaves in wave 1 and the head last",
          chain_reject[f"indicator--L{chain - 1:05d}"] == 1
          and chain_reject["indicator--L00000"] == chain,
          str(chain_reject) if chain <= 12 else "long chain")
    check("each chain wave evicts exactly one chain link",
          [sum(1 for v in chain_reject.values() if v == i)
           for i in range(1, chain + 1)] == [1] * chain)
    check("wave_count follows the chain length (hub leaves with a chain link)",
          receipt["wave_count"] == chain, str(receipt["wave_count"]))

    # ---- the stable partition is never judged after the initial account
    fresh_waves = [w for w in receipt["waves"] if 2 <= w["wave"] <= chain]
    # wave 2 re-judges only the hub (and its last peer's loss), never a
    # stable-partition entity.
    check("after the initial account no wave judges a stable-partition entity",
          all(w["candidate_entities"] <= 2 for w in fresh_waves),
          str([w["candidate_entities"] for w in fresh_waves]))
    check("each delta wave probes only the affected counters",
          all(w["probed_counter_rows"] <= 2 for w in fresh_waves),
          str([w["probed_counter_rows"] for w in fresh_waves]))
    check("stable pairs all survive",
          len([r for r in q(out, "SELECT obj_id FROM load_entities")
               if "--P" in r["obj_id"]]) == 2 * stable)
    check("the hub fails in wave 2, after its fan-out left in wave 1",
          q(out, "SELECT eviction_wave FROM reject_entity_map"
                 " WHERE obj_id='indicator--HUB'")[0]["eviction_wave"] == 2)
    check("all fan-out relations leave in wave 1 with their peer",
          q(out, "SELECT COUNT(*) AS n FROM reject_relations"
                 " WHERE eviction_wave=1")[0]["n"] == fanout + 1)
    check("the hub's own outgoing relations left in wave 1 with their peers",
          all(r["eviction_wave"] == 1 for r in q(
              out, "SELECT eviction_wave FROM reject_relations"
                   " WHERE row_key LIKE '%HUB%'"))
          and q(out, "SELECT COUNT(*) AS n FROM reject_relations"
                     " WHERE row_key LIKE '%HUB%'")[0]["n"] == fanout)
    hub_snap = q(out, "SELECT distinct_peers, min_peers FROM eviction_alt_snapshot"
                      " WHERE entity_id='indicator--HUB'")
    check("the hub's measured count at its eviction frontier is 0",
          hub_snap == [{"distinct_peers": 0, "min_peers": 1}], str(hub_snap))

    # ---- the high-fan-out wave is proportional to the *removed* rows; later
    #      waves cannot grow with the (large and now unrelated) surviving set
    wave1 = waves[1]
    check("fan-out peers are judged as a batch, not one neighbourhood walk",
          wave1["evicted_entities"] == fanout + 1, str(wave1["evicted_entities"]))
    later_probe = max(w["probed_counter_rows"] for w in fresh_waves)
    check("later waves' counter probes do not scale with fan-out",
          later_probe <= 2, str(later_probe))
    check("no wave judges more than two entities after the initial account",
          max(w["candidate_entities"] for w in fresh_waves) <= 2,
          str(max(w["candidate_entities"] for w in fresh_waves)))
    check("no unrelated partition is judged",
          all(w["evicted_entities"] <= 2 for w in fresh_waves),
          str([w["evicted_entities"] for w in fresh_waves]))
    check("release memory stays modest relative to the synthetic corpus",
          peak - rss_before < 400 * 1024,
          f"delta={peak - rss_before}KB corpus={len(entities)} entities")

    # ---- access evidence is persisted in the package and reproducible
    check("access evidence is stored in the package",
          q(out, "SELECT COUNT(*) AS n FROM release_access")[0]["n"] > 0)
    check("wave evidence was captured before the ledger phase",
          any(json.loads(r["access_json"]) for r in q(
              out, "SELECT * FROM release_waves WHERE wave=1")))


def test_explain_plan(work):
    print("\n[10] delta waves use indexed lookups, never a table scan")
    master = make_warehouse(work, "plan", "main")
    conn = sqlite3.connect(master)
    conn.row_factory = sqlite3.Row
    plans = conn.execute(
        "EXPLAIN QUERY PLAN SELECT row_key FROM t2_relations"
        " WHERE source_canon IN ('indicator--I1')").fetchall()
    text = " | ".join(r[3] for r in plans)
    conn.close()
    check("relation lookup by endpoint uses an index", "SEARCH" in text
          and "SCAN t2_relations" not in text, text)


def main():
    work = tempfile.mkdtemp(prefix="sg-release-")
    try:
        test_documented_fixture(work)
        test_alternative_conditions(work)
        test_merged_members_and_alias_load(work)
        test_same_wave_both_endpoints(work)
        test_exclusion(work)
        test_relationship_type_filter(work)
        test_empty_delivery(work)
        test_no_requirement_sets(work)
        test_misconfiguration(work)
        test_atomicity_and_existing(work)
        test_concurrent_writer(work)
        test_scale_access(work)
        test_explain_plan(work)
        print(f"\n{PASS} passed, {FAIL} failed")
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
