#!/usr/bin/env python3
"""Master-warehouse end-to-end verification.

Drives the public CLI (``sg-cli.py master-*``) as subprocesses against a
synthetic projection package, plus a few in-process library calls for the
fault-injection and concurrency cases.  An independent consumer reconstructs
the four logical tables solely from revision-0 reads plus per-revision change
records — never recomputing identities itself — and its view is compared with
both a full read and hand-written expectations.

Run:  python3 -I tests/run_master_verify.py
Scale knob: SG_MASTER_SCALE=2000 python3 -I tests/run_master_verify.py
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "sg-cli.py")
sys.path.insert(0, ROOT)

from tests.master_fixtures import build_package, build_scale_batches  # noqa: E402
from sg import master as MD  # noqa: E402
from sg.util import SGError  # noqa: E402

PASS = FAIL = 0
SCALE = int(os.environ.get("SG_MASTER_SCALE", "300"))


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}", flush=True)
    else:
        FAIL += 1
        print(f"  FAIL  {label}  {detail}", flush=True)


def run_cli(*args):
    p = subprocess.run([sys.executable, "-I", CLI, *args],
                       cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def write_batch(work, name, doc):
    path = os.path.join(work, name)
    with open(path, "wb") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    return path


# ------------------------------------------------- independent change consumer ----

class Consumer:
    """Reconstructs the four tables using only snapshot + change feed."""

    def __init__(self, snapshot):
        self.revision = snapshot["revision"]
        self.tables = {t: {} for t in MD.TABLE_ORDER}
        key_col = {MD.T_ENTITY: "obj_id", MD.T_REL: "row_key",
                   MD.T_CONTRIB: "relationship_id", MD.T_VERDICT: "verdict_id"}
        for t in MD.TABLE_ORDER:
            for row in snapshot["tables"][t]:
                self.tables[t][row[key_col[t]]] = row

    def apply_changes(self, master, rev_from, rev_to):
        for item in MD.read_changes(master, rev_from, rev_to):
            if item["type"] == "revision_header":
                check(f"rev{item['revision']} header parent linkage",
                      item["parent_revision"] == self.revision)
                continue
            t, key, op = item["table"], item["row_key"], item["op"]
            if op == "delete":
                assert key in self.tables[t], (t, key)
                del self.tables[t][key]
            else:
                self.tables[t][key] = item["row"]
        self.revision = rev_to

    def view(self):
        return {t: [self.tables[t][k] for k in sorted(self.tables[t])]
                for t in MD.TABLE_ORDER}


def full_view(master):
    snap = MD.read_all(master)
    key_col = {MD.T_ENTITY: "obj_id", MD.T_REL: "row_key",
               MD.T_CONTRIB: "relationship_id", MD.T_VERDICT: "verdict_id"}
    return {t: {row[key_col[t]]: row for row in snap["tables"][t]}
            for t in MD.TABLE_ORDER}, snap["revision"]


# --------------------------------------------------------------------- tests ----

def test_main_scenario(work):
    print("\n[1] build + first-round adjudication + retraction walk-through")
    pkg = os.path.join(work, "pkg.sqlite")
    build_package(pkg, scale=0)
    mpath = os.path.join(work, "main.sqlite")
    rc, out, err = run_cli("master-build", "--package", pkg, "--master", mpath)
    check("master-build rc0", rc == 0, err)
    rc, out, err = run_cli("master-build", "--package", pkg, "--master", mpath)
    check("rebuild refused (one package per warehouse)", rc == 2, err)
    errdoc = json.loads(err)
    check("rebuild error code", errdoc["error"] == "master-exists", err)

    ctx = json.loads(run_cli("master-context", "--master", mpath)[1])
    check("context registers package digest and audience",
          ctx["principal"] == "carol" and len(ctx["package_digest_sha256"]) == 64
          and ctx["codename"] == "C-SYNTH", json.dumps(ctx)[:200])
    check("base counts", ctx["base_entity_count"] == "5"
          and ctx["base_edge_count"] == "3", ctx)

    snap0 = MD.read_all(mpath)
    check("revision 0 after build", snap0["revision"] == 0)
    check("identity mapping exists with no verdicts",
          {r["obj_id"]: r["canonical_id"] for r in snap0["tables"]["entity_map"]}
          == {f"indicator--{x}": f"indicator--{x}" for x in "ABCDE"})
    check("rev0 relations unmerged",
          {r["row_key"]: r["contribution_count"]
           for r in snap0["tables"]["relations"]} ==
          {MD._row_key("indicator--A", "indicates", "indicator--E"): 1,
           MD._row_key("indicator--C", "indicates", "indicator--E"): 1,
           MD._row_key("indicator--E", "indicates", "indicator--C"): 1})
    check("rev0 empty verdict table", snap0["tables"]["verdicts"] == [])
    rev0 = MD.list_revisions(mpath)
    check("revision 0 header readable", len(rev0) == 1 and rev0[0]["note"] == "build")

    b1 = write_batch(work, "b1.json", {
        "batch_id": "B1", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "V-AB", "kind": "same",
             "a": "indicator--A", "b": "indicator--B", "priority": 3},
            {"op": "put", "verdict_id": "V-BC", "kind": "same",
             "a": "indicator--B", "b": "indicator--C", "priority": 2},
            {"op": "put", "verdict_id": "V-CD", "kind": "same",
             "a": "indicator--C", "b": "indicator--D", "priority": 1},
            {"op": "put", "verdict_id": "V-AD", "kind": "different",
             "a": "indicator--A", "b": "indicator--D"}]})
    rc, out, err = run_cli("master-apply", "--master", mpath, "--batch", b1)
    check("B1 applied", rc == 0, err)
    receipt = json.loads(out)
    check("B1 revision", receipt["published_revision"] == 1
          and receipt["parent_revision"] == 0)

    # identical byte resend: same revision, never refused, never re-applied
    rc2, out2, err2 = run_cli("master-apply", "--master", mpath, "--batch", b1)
    check("identical resend accepted as dedup", rc2 == 0 and
          json.loads(out2)["deduplicated"] is True and
          json.loads(out2)["published_revision"] == 1, err2)
    check("still only two revisions", len(MD.list_revisions(mpath)) == 2)

    view1, rev = full_view(mpath)
    captured = {1: {t: dict(rows) for t, rows in view1.items()}}
    check("head revision 1", rev == 1)
    canon1 = {k: r["canonical_id"] for k, r in view1["entity_map"].items()}
    check("A,B,C merged; D alone; E alone",
          canon1 == {"indicator--A": "indicator--A", "indicator--B": "indicator--A",
                     "indicator--C": "indicator--A", "indicator--D": "indicator--D",
                     "indicator--E": "indicator--E"}, str(canon1))
    v4 = {k: (r["result"], r["blocking_verdict_id"])
          for k, r in view1["verdicts"].items()}
    check("V-CD blocked by V-AD",
          v4["V-CD"] == ("blocked", "V-AD"), str(v4))
    check("V-AD is a constraint", v4["V-AD"] == ("constraint", None))
    rels1 = {r["row_key"]: r for r in view1["relations"].values()}
    k_ae = MD._row_key("indicator--A", "indicates", "indicator--E")
    k_ea = MD._row_key("indicator--E", "indicates", "indicator--A")
    check("A->E and C->E merged with contribution 2",
          rels1[k_ae]["contribution_count"] == 2 and rels1[k_ae]["is_self_loop"] == 0)
    check("reverse edge kept separate",
          k_ea in rels1 and rels1[k_ea]["contribution_count"] == 1)
    check("no spurious third relation", len(rels1) == 2)
    contribs1 = {k: r["row_key"] for k, r in view1["contributions"].items()}
    check("both original relationship ids traceable to merged key",
          contribs1["relationship--R1"] == k_ae
          and contribs1["relationship--R2"] == k_ae
          and contribs1["relationship--R3"] == k_ea)
    c3 = view1["contributions"]["relationship--R1"]
    check("contribution keeps original coordinates",
          c3["modified_key"] == 1767225600000000 and c3["modified_raw"]
          == "2026-01-01T00:00:00Z" and c3["source_id"] == "indicator--A")

    # ---- second round: retract V-BC ----
    b2 = write_batch(work, "b2.json", {
        "batch_id": "B2", "expected_parent": 1, "operations": [
            {"op": "retract", "verdict_id": "V-BC"}]})
    rc, out, err = run_cli("master-apply", "--master", mpath, "--batch", b2)
    check("B2 applied", rc == 0, err)
    view2, rev = full_view(mpath)
    captured[2] = {t: dict(rows) for t, rows in view2.items()}
    check("head revision 2", rev == 2)
    canon2 = {k: r["canonical_id"] for k, r in view2["entity_map"].items()}
    check("split into {A,B} and {C,D}",
          canon2 == {"indicator--A": "indicator--A", "indicator--B": "indicator--A",
                     "indicator--C": "indicator--C", "indicator--D": "indicator--C",
                     "indicator--E": "indicator--E"}, str(canon2))
    v4b = {k: r["result"] for k, r in view2["verdicts"].items()}
    check("V-CD becomes merged after retraction", v4b["V-CD"] == "merged")
    check("V-BC removed from active verdict table", "V-BC" not in view2["verdicts"])
    rels2 = {r["row_key"]: r for r in view2["relations"].values()}
    check("forward relations split, each contribution 1",
          rels2[MD._row_key("indicator--A", "indicates", "indicator--E")]
          ["contribution_count"] == 1
          and rels2[MD._row_key("indicator--C", "indicates", "indicator--E")]
          ["contribution_count"] == 1)
    check("reverse edge re-pointed E->C",
          MD._row_key("indicator--E", "indicates", "indicator--C") in rels2
          and MD._row_key("indicator--E", "indicates", "indicator--A") not in rels2)

    # ---- independent consumer: rev0 snapshot + change feed only.
    # It never recomputes identities; each step's reconstructed tables are
    # compared against the full-read snapshot captured at that same revision.
    consumer = Consumer(snap0)
    consumer.apply_changes(mpath, 1, 1)
    check("consumer matches full read at rev1",
          all(consumer.tables[t] == captured[1][t] for t in MD.TABLE_ORDER))
    consumer.apply_changes(mpath, 2, 2)
    check("consumer matches full read at rev2 without recomputing entities",
          all(consumer.tables[t] == captured[2][t] for t in MD.TABLE_ORDER))
    check("consumer revision pointer", consumer.revision == 2)
    # and the reconstructed rev2 view also equals the warehouse head read now.
    check("captured rev2 equals current full read",
          all(captured[2][t] == view2[t] for t in MD.TABLE_ORDER))

    # change feed determinism: same order on repeated reads
    first = list(MD.read_changes(mpath, 1, 2))
    second = list(MD.read_changes(mpath, 1, 2))
    check("change feed order is deterministic", first == second)
    # unchanged rows are never re-sent: rev2 changes only touch region keys
    rev2_rows = [x for x in first if x["type"] == "change"
                 and x["revision"] == 2]
    touched_entities = {x["row_key"] for x in rev2_rows
                        if x["table"] == "entity_map"}
    check("only moved entities appear in rev2 map diff",
          touched_entities == {"indicator--C", "indicator--D"},
          str(touched_entities))


def test_orientation_and_batch_rules(work):
    print("\n[2] endpoint orientation, validation, generic errors")
    pkg = os.path.join(work, "pkg2.sqlite")
    build_package(pkg, scale=0)
    mpath = os.path.join(work, "m2.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)

    # reversed endpoints must produce the same canonical stored pair
    b = write_batch(work, "rev.json", {
        "batch_id": "BX", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "V1", "kind": "same",
             "a": "indicator--B", "b": "indicator--A", "priority": 1}]})
    rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", b)
    check("reversed endpoints accepted", rc == 0, err)
    view, _ = full_view(mpath)
    row = view["verdicts"]["V1"]
    check("stored pair canonicalized",
          row["endpoint_a"] == "indicator--A" and row["endpoint_b"] == "indicator--B")

    # duplicate verdict id inside one batch
    bad = write_batch(work, "dup.json", {
        "batch_id": "BX2", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "X", "kind": "same",
             "a": "indicator--A", "b": "indicator--C", "priority": 1},
            {"op": "put", "verdict_id": "X", "kind": "different",
             "a": "indicator--A", "b": "indicator--C"}]})
    rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", bad)
    check("duplicate verdict id rejected", rc == 2)
    check("generic error, no endpoint echo",
          "indicator--" not in err and json.loads(err)["error"] == "batch-rejected")

    # unknown endpoint / different types / equal endpoints / missing priority
    cases = [
        {"batch_id": "E1", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "E", "kind": "same",
             "a": "indicator--NOPE", "b": "indicator--A", "priority": 1}]},
        {"batch_id": "E2", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "E", "kind": "same",
             "a": "indicator--A", "b": "indicator--A", "priority": 1}]},
        {"batch_id": "E3", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "E", "kind": "different",
             "a": "indicator--A", "b": "indicator--B", "priority": 3}]},
        {"batch_id": "E4", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "E", "kind": "same",
             "a": "indicator--A", "b": "indicator--B"}]},
        {"batch_id": "E5", "expected_parent": 1, "operations": [
            {"op": "retract", "verdict_id": "never-existed"}]},
    ]
    for i, doc in enumerate(cases):
        p = write_batch(work, f"bad{i}.json", doc)
        rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", p)
        check(f"invalid batch {i} rejected generically",
              rc == 2 and json.loads(err)["error"] == "batch-rejected"
              and "indicator--" not in err, err.strip())
    check("no revision published by invalid batches",
          [r["revision"] for r in MD.list_revisions(mpath)] == [0, 1])

    # stale parent
    stale = write_batch(work, "stale.json", {
        "batch_id": "ST", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "S", "kind": "different",
             "a": "indicator--C", "b": "indicator--D"}]})
    rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", stale)
    check("stale parent rejected",
          rc == 2 and json.loads(err)["error"] == "stale-parent-revision")

    # same batch id, different bytes
    conflict = write_batch(work, "conflict.json", {
        "batch_id": "BX", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "V9", "kind": "different",
             "a": "indicator--C", "b": "indicator--D"}]})
    rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", conflict)
    check("same batch id different bytes rejected",
          rc == 2 and json.loads(err)["error"] == "batch-id-conflict")


def test_same_priority_order(work):
    print("\n[3] equal-priority tie broken by verdict id UTF-8 byte order")
    pkg = os.path.join(work, "pkg3.sqlite")
    build_package(pkg, scale=0)
    mpath = os.path.join(work, "m3.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)
    # same priority; ids chosen so processing order is V-a, V-b, V-c.
    # different A-D means only one of the two D-touching merges can succeed;
    # the byte-minimum verdict id gets the merge.
    doc = {"batch_id": "P1", "expected_parent": 0, "operations": [
        {"op": "put", "verdict_id": "V-c", "kind": "same",
         "a": "indicator--C", "b": "indicator--D", "priority": 5},
        {"op": "put", "verdict_id": "V-a", "kind": "same",
         "a": "indicator--A", "b": "indicator--B", "priority": 5},
        {"op": "put", "verdict_id": "V-b", "kind": "same",
         "a": "indicator--B", "b": "indicator--C", "priority": 5},
        {"op": "put", "verdict_id": "V-d", "kind": "different",
         "a": "indicator--A", "b": "indicator--D"}]}
    run_cli("master-apply", "--master", mpath, "--batch",
            write_batch(work, "p1.json", doc))
    view, _ = full_view(mpath)
    results = {k: r["result"] for k, r in view["verdicts"].items()}
    check("byte-min same-priority id merges first",
          results["V-a"] == "merged" and results["V-b"] == "merged")
    check("later same-priority candidate blocked",
          results["V-c"] == "blocked"
          and view["verdicts"]["V-c"]["blocking_verdict_id"] == "V-d")
    canon = {k: r["canonical_id"] for k, r in view["entity_map"].items()}
    check("group canonical is byte-min member",
          canon["indicator--C"] == "indicator--A"
          and canon["indicator--D"] == "indicator--D")


def test_blocking_evidence_switch(work):
    print("\n[4] multiple blockers: evidence-only revision switches blocker id")
    pkg = os.path.join(work, "pkg4.sqlite")
    build_package(pkg, scale=0, extra_edges=[])
    mpath = os.path.join(work, "m4.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)
    # Two different verdicts between the same two eventual groups.
    doc1 = {"batch_id": "D1", "expected_parent": 0, "operations": [
        {"op": "put", "verdict_id": "V-block-hi", "kind": "different",
         "a": "indicator--A", "b": "indicator--D"},
        {"op": "put", "verdict_id": "V-block-lo", "kind": "different",
         "a": "indicator--B", "b": "indicator--D"},
        {"op": "put", "verdict_id": "V-grp1", "kind": "same",
         "a": "indicator--A", "b": "indicator--B", "priority": 5},
        {"op": "put", "verdict_id": "V-cd", "kind": "same",
         "a": "indicator--C", "b": "indicator--D", "priority": 5},
        {"op": "put", "verdict_id": "V-bc", "kind": "same",
         "a": "indicator--B", "b": "indicator--C", "priority": 1}]}
    run_cli("master-apply", "--master", mpath, "--batch",
            write_batch(work, "d1.json", doc1))
    view, _ = full_view(mpath)
    check("smallest different id is the recorded blocker",
          view["verdicts"]["V-bc"]["blocking_verdict_id"] == "V-block-hi")
    canon_before = {k: r["canonical_id"] for k, r in view["entity_map"].items()}

    # retract the byte-min blocker: mapping stays identical but the evidence
    # recorded on the blocked verdict must change -> a revision is still due.
    doc2 = {"batch_id": "D2", "expected_parent": 1, "operations": [
        {"op": "retract", "verdict_id": "V-block-hi"}]}
    rc, out, err = run_cli("master-apply", "--master", mpath,
                           "--batch", write_batch(work, "d2.json", doc2))
    check("evidence switch revision applied", rc == 0, err)
    view2, rev = full_view(mpath)
    canon_after = {k: r["canonical_id"] for k, r in view2["entity_map"].items()}
    check("member mapping unchanged", canon_before == canon_after)
    check("blocker evidence switched to the remaining minimum id",
          view2["verdicts"]["V-bc"]["result"] == "blocked"
          and view2["verdicts"]["V-bc"]["blocking_verdict_id"] == "V-block-lo")
    changes = [x for x in MD.read_changes(mpath, 2, 2) if x["type"] == "change"]
    check("evidence change is still delivered",
          any(c["table"] == "verdicts" and c["row_key"] == "V-bc" for c in changes)
          and not any(c["table"] == "entity_map" for c in changes))


def test_self_loop(work):
    print("\n[5] merged endpoints keep a flagged self-loop; split removes it")
    pkg = os.path.join(work, "pkg5.sqlite")
    build_package(pkg, scale=0, extra_edges=[
        ("relationship--R4", "indicator--A", "indicator--B", "indicates")])
    mpath = os.path.join(work, "m5.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)
    doc = {"batch_id": "L1", "expected_parent": 0, "operations": [
        {"op": "put", "verdict_id": "V-ab", "kind": "same",
         "a": "indicator--A", "b": "indicator--B", "priority": 5}]}
    run_cli("master-apply", "--master", mpath,
            "--batch", write_batch(work, "l1.json", doc))
    view, _ = full_view(mpath)
    sl_key = MD._row_key("indicator--A", "indicates", "indicator--A")
    check("self-loop row exists and is flagged",
          sl_key in view["relations"]
          and view["relations"][sl_key]["is_self_loop"] == 1
          and view["contributions"]["relationship--R4"]["is_self_loop"] == 1)
    check("self-loop has contribution detail",
          view["contributions"]["relationship--R4"]["row_key"] == sl_key)
    doc2 = {"batch_id": "L2", "expected_parent": 1, "operations": [
        {"op": "retract", "verdict_id": "V-ab"}]}
    run_cli("master-apply", "--master", mpath,
            "--batch", write_batch(work, "l2.json", doc2))
    view2, _ = full_view(mpath)
    check("self-loop removed after split",
          sl_key not in view2["relations"]
          and view2["contributions"]["relationship--R4"]["is_self_loop"] == 0)
    changes = [x for x in MD.read_changes(mpath, 2, 2) if x["type"] == "change"]
    check("self-loop deletion recorded in change feed",
          any(c["table"] == "relations" and c["row_key"] == sl_key
              and c["op"] == "delete" for c in changes))


def test_empty_diff_and_replace(work):
    print("\n[6] empty-diff revision header and put replacement semantics")
    pkg = os.path.join(work, "pkg6.sqlite")
    build_package(pkg, scale=0)
    mpath = os.path.join(work, "m6.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)

    # An empty operations list changes nothing at all: it still publishes a
    # revision whose header is readable and whose change feed has only the
    # header line.
    empty = write_batch(work, "n0.json", {
        "batch_id": "N0", "expected_parent": 0, "operations": []})
    rc, out, _ = run_cli("master-apply", "--master", mpath, "--batch", empty)
    check("empty batch published with zero changes",
          rc == 0 and json.loads(out)["change_count"] == 0)
    headers = [x for x in MD.read_changes(mpath, 1, 1)]
    check("empty revision still emits its header",
          len(headers) == 1 and headers[0]["type"] == "revision_header"
          and headers[0]["change_count"] == 0)

    # a `different` verdict between otherwise unconnected entities changes no
    # groups/mapping/relations; only its own T4 row is delivered.
    doc = {"batch_id": "N1", "expected_parent": 1, "operations": [
        {"op": "put", "verdict_id": "V-ad", "kind": "different",
         "a": "indicator--A", "b": "indicator--D"}]}
    rc, out, _ = run_cli("master-apply", "--master", mpath,
                         "--batch", write_batch(work, "n1.json", doc))
    receipt = json.loads(out)
    check("constraint-only batch published", rc == 0)
    changes = [x for x in MD.read_changes(mpath, 2, 2) if x["type"] == "change"]
    check("only the verdict row changes, no map/relation rows",
          len(changes) == 1 and changes[0]["table"] == "verdicts"
          and changes[0]["row_key"] == "V-ad", str(changes))
    # identical resend of the empty batch returns its original revision.
    rc, out2, _ = run_cli("master-apply", "--master", mpath,
                          "--batch", empty)
    check("resend does not create another revision",
          len(MD.list_revisions(mpath)) == 3 and
          json.loads(out2)["deduplicated"] is True
          and json.loads(out2)["published_revision"] == 1)

    # replace a verdict: same id, different kind/priority/endpoints
    doc2 = {"batch_id": "N2", "expected_parent": 2, "operations": [
        {"op": "put", "verdict_id": "V-ad", "kind": "same",
         "a": "indicator--A", "b": "indicator--B", "priority": 9}]}
    run_cli("master-apply", "--master", mpath,
            "--batch", write_batch(work, "n2.json", doc2))
    view, _ = full_view(mpath)
    check("put replaced the existing verdict",
          view["verdicts"]["V-ad"]["kind"] == "same"
          and view["verdicts"]["V-ad"]["priority"] == 9
          and view["entity_map"]["indicator--B"]["canonical_id"] == "indicator--A")
    # retract must only target currently active verdicts
    doc3 = {"batch_id": "N3", "expected_parent": 3, "operations": [
        {"op": "retract", "verdict_id": "V-ad"}]}
    run_cli("master-apply", "--master", mpath,
            "--batch", write_batch(work, "n3.json", doc3))
    doc4 = {"batch_id": "N4", "expected_parent": 4, "operations": [
        {"op": "retract", "verdict_id": "V-ad"}]}
    rc, _, err = run_cli("master-apply", "--master", mpath,
                         "--batch", write_batch(work, "n4.json", doc4))
    check("retracting an already-retracted verdict refused", rc == 2
          and json.loads(err)["error"] == "batch-rejected")


def test_concurrent_writers(work):
    print("\n[7] two writers, same parent, different batches: at most one wins")
    pkg = os.path.join(work, "pkg7.sqlite")
    build_package(pkg, scale=0)
    mpath = os.path.join(work, "m7.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)
    b1 = write_batch(work, "c1.json", {
        "batch_id": "C1", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "W1", "kind": "different",
             "a": "indicator--A", "b": "indicator--B"}]})
    b2 = write_batch(work, "c2.json", {
        "batch_id": "C2", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "W2", "kind": "different",
             "a": "indicator--C", "b": "indicator--D"}]})
    results = []

    def worker(batch):
        try:
            r = MD.apply_batch(mpath, open(batch, "rb").read())
            results.append(("ok", r["batch_id"], r["published_revision"]))
        except SGError as exc:
            results.append(("err", exc.code, None))

    t1 = threading.Thread(target=worker, args=(b1,))
    t2 = threading.Thread(target=worker, args=(b2,))
    t1.start(); t2.start(); t1.join(); t2.join()
    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    check("exactly one writer committed",
          len(oks) == 1 and len(errs) == 1, str(results))
    check("losser rejected as stale parent",
          errs[0][1] == "stale-parent-revision", str(results))
    revs = MD.list_revisions(mpath)
    check("warehouse advanced exactly one revision",
          [r["revision"] for r in revs] == [0, 1])
    # the loser can be resubmitted against the new parent and then succeeds
    loser = b2 if oks[0][1] == "C1" else b1
    doc = json.loads(open(loser, "rb").read())
    doc["expected_parent"] = 1
    fixed = write_batch(work, "cfix.json", doc)
    rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", fixed)
    check("loser retried on new parent succeeds", rc == 0, err)
    check("two batches eventually both durable",
          len(MD.list_revisions(mpath)) == 3)


def test_crash_and_resend(work):
    print("\n[8] fault before commit: reopen sees only the complete old state")
    pkg = os.path.join(work, "pkg8.sqlite")
    build_package(pkg, scale=0)
    mpath = os.path.join(work, "m8.sqlite")
    run_cli("master-build", "--package", pkg, "--master", mpath)
    b = write_batch(work, "crash.json", {
        "batch_id": "K1", "expected_parent": 0, "operations": [
            {"op": "put", "verdict_id": "K-ab", "kind": "same",
             "a": "indicator--A", "b": "indicator--B", "priority": 5}]})
    env = dict(os.environ, SG_MASTER_FAULT="1")
    p = subprocess.run([sys.executable, "-I", CLI, "master-apply",
                        "--master", mpath, "--batch", b],
                       cwd=ROOT, capture_output=True, text=True, env=env)
    check("faulting apply exits non-zero", p.returncode != 0, p.stderr)
    revs = MD.list_revisions(mpath)
    check("no revision published after fault",
          [r["revision"] for r in revs] == [0])
    view, rev = full_view(mpath)
    check("tables still at revision 0", rev == 0 and
          view["entity_map"]["indicator--B"]["canonical_id"] == "indicator--B"
          and view["verdicts"] == {})
    # no receipt, no change rows, no adjudications left behind
    conn = sqlite3.connect(mpath)
    n_adj = conn.execute("SELECT COUNT(*) FROM adjudications").fetchone()[0]
    n_chg = conn.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
    n_rec = conn.execute("SELECT COUNT(*) FROM batch_receipts").fetchone()[0]
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()
    check("no partial ledger/change/receipt rows",
          n_adj == 0 and n_chg == 0 and n_rec == 0)
    check("sqlite integrity intact", integrity == "ok")
    # resend the identical batch without the fault: accepted as a fresh apply
    rc, out, err = run_cli("master-apply", "--master", mpath, "--batch", b)
    check("resend after crash publishes revision 1",
          rc == 0 and json.loads(out)["published_revision"] == 1
          and json.loads(out)["deduplicated"] is False, err)


def test_relationship_filtering(work):
    print("\n[9] build-time relationship body/edge consistency filtering")
    # hand-craft a package with invalid edges and non-entity endpoints
    path = os.path.join(work, "pkg9.sqlite")
    sys.path.insert(0, ROOT)
    from sg.projection import PROJ_SCHEMA
    if os.path.exists(path):
        os.unlink(path)
    c = sqlite3.connect(path)
    c.executescript(PROJ_SCHEMA)
    ts, mk = "2026-01-01T00:00:00Z", 1767225600000000

    def obj(oid, t, doc):
        c.execute("INSERT INTO objects VALUES(?,?,?,?,?,?)",
                  (oid, t, mk, ts, json.dumps(doc), json.dumps(doc)))

    for eid in ("indicator--A", "indicator--B", "indicator--C"):
        obj(eid, "indicator", {"type": "indicator", "id": eid, "modified": ts})
    obj("report--X", "report", {"type": "report", "id": "report--X"})
    # good edge
    obj("relationship--OK", "relationship",
        {"type": "relationship", "id": "relationship--OK", "modified": ts,
         "relationship_type": "indicates", "source_ref": "indicator--A",
         "target_ref": "indicator--B"})
    c.execute("INSERT INTO edges VALUES(?,?,?,?)",
              ("relationship--OK", "indicator--A", "indicator--B", mk))
    # body disagrees with the edge
    obj("relationship--MISMATCH", "relationship",
        {"type": "relationship", "id": "relationship--MISMATCH",
         "modified": ts, "relationship_type": "indicates",
         "source_ref": "indicator--A", "target_ref": "indicator--C"})
    c.execute("INSERT INTO edges VALUES(?,?,?,?)",
              ("relationship--MISMATCH", "indicator--C", "indicator--A", mk))
    # empty relationship_type
    obj("relationship--EMPTY", "relationship",
        {"type": "relationship", "id": "relationship--EMPTY", "modified": ts,
         "relationship_type": "", "source_ref": "indicator--A",
         "target_ref": "indicator--B"})
    c.execute("INSERT INTO edges VALUES(?,?,?,?)",
              ("relationship--EMPTY", "indicator--A", "indicator--B", mk))
    # endpoint not an entity base row (report)
    obj("relationship--NONENT", "relationship",
        {"type": "relationship", "id": "relationship--NONENT", "modified": ts,
         "relationship_type": "indicates", "source_ref": "indicator--A",
         "target_ref": "report--X"})
    c.execute("INSERT INTO edges VALUES(?,?,?,?)",
              ("relationship--NONENT", "indicator--A", "report--X", mk))
    # edge references a missing relationship body
    c.execute("INSERT INTO edges VALUES(?,?,?,?)",
              ("relationship--GHOST", "indicator--A", "indicator--B", mk))
    for k, v in [("schema", "stix-gate-projection/1"), ("codename", "C9"),
                 ("t_key", str(mk)), ("principal", "carol"),
                 ("policy_digest", "d"), ("signing_key", "00"),
                 ("t_raw", "2026-02-01T00:00:00Z")]:
        c.execute("INSERT INTO meta VALUES(?,?)", (k, v))
    c.commit(); c.close()

    mpath = os.path.join(work, "m9.sqlite")
    rc, out, err = run_cli("master-build", "--package", path, "--master", mpath)
    check("build with bad edges succeeds", rc == 0, err)
    ctx = json.loads(run_cli("master-context", "--master", mpath)[1])
    check("exactly one edge kept, four rejected",
          ctx["base_edge_count"] == "1" and ctx["rejected_edge_count"] == "4",
          json.dumps(ctx))
    view, _ = full_view(mpath)
    check("report excluded from entity base",
          "report--X" not in view["entity_map"]
          and len(view["entity_map"]) == 3)
    check("only the valid relation present",
          list(view["relations"]) == [
              MD._row_key("indicator--A", "indicates", "indicator--B")])


def test_scale_access_scope(work):
    print(f"\n[10] scale filler ({SCALE} blocks): access scope stays local")
    pkg = os.path.join(work, "pkgB.sqlite")
    build_package(pkg, scale=SCALE)
    mpath = os.path.join(work, "mB.sqlite")
    rc, _, err = run_cli("master-build", "--package", pkg, "--master", mpath)
    check("scaled build ok", rc == 0, err)

    # activate the filler partition in one big batch (full-graph activation;
    # access counters here are not judged, only the later correction batch).
    filler_ops = build_scale_batches(work, SCALE)
    fb = write_batch(work, "filler.json", {
        "batch_id": "FILL", "expected_parent": 0, "operations": filler_ops})
    rc, _, err = run_cli("master-apply", "--master", mpath, "--batch", fb)
    check("filler batch applied", rc == 0, err)
    small = write_batch(work, "small.json", {
        "batch_id": "MAIN1", "expected_parent": 1, "operations": [
            {"op": "put", "verdict_id": "V-AB", "kind": "same",
             "a": "indicator--A", "b": "indicator--B", "priority": 3},
            {"op": "put", "verdict_id": "V-BC", "kind": "same",
             "a": "indicator--B", "b": "indicator--C", "priority": 2},
            {"op": "put", "verdict_id": "V-CD", "kind": "same",
             "a": "indicator--C", "b": "indicator--D", "priority": 1},
            {"op": "put", "verdict_id": "V-AD", "kind": "different",
             "a": "indicator--A", "b": "indicator--D"}]})
    rc, out, err = run_cli("master-apply", "--master", mpath,
                           "--batch", small)
    check("small-region batch applied over big warehouse", rc == 0, err)
    receipt = json.loads(out)
    access = receipt["access"]["batch"]
    data_tables = ["base_objects", "base_edges", "adjudications",
                   "t1_entity_map", "t2_relations", "t3_contributions",
                   "t4_verdicts"]
    scans = {t: access.get(t, {}).get("scan", 0) for t in data_tables}
    check("zero full scans on all data tables",
          all(v == 0 for v in scans.values()), str(scans))
    # the tiny bookkeeping tables are exempt (MAX(revision), receipt lookup)
    touched = sum(access.get(t, {}).get("filtered", 0) for t in data_tables)
    check("filtered access count independent of filler size",
          touched < 200, f"touched={touched} scale={SCALE}")

    # second small correction (retract V-BC): access scope must stay bounded
    b2 = write_batch(work, "small2.json", {
        "batch_id": "MAIN2", "expected_parent": 2, "operations": [
            {"op": "retract", "verdict_id": "V-BC"}]})
    rc, out, err = run_cli("master-apply", "--master", mpath, "--batch", b2)
    check("scaled correction applied", rc == 0, err)
    access2 = json.loads(out)["access"]["batch"]
    scans2 = {t: access2.get(t, {}).get("scan", 0) for t in data_tables}
    touched2 = sum(access2.get(t, {}).get("filtered", 0) for t in data_tables)
    check("correction also has zero data-table scans",
          all(v == 0 for v in scans2.values()), str(scans2))
    check("correction access count stays small",
          touched2 < 200, f"touched={touched2} scale={SCALE}")

    # filler partition results must be untouched by the small correction
    view, rev = full_view(mpath)
    check("filler mapping intact",
          view["entity_map"][f"indicator--Z000000"]["canonical_id"]
          == f"indicator--Y000000"  # same-pair merge: Y < Z in byte order
          and view["entity_map"][f"indicator--Z{SCALE-1:06d}"]["canonical_id"]
          == f"indicator--Y{SCALE-1:06d}")
    check("filler verdicts still active",
          f"verdict--ZS{SCALE-1:06d}" in view["verdicts"])

    # EXPLAIN QUERY PLAN evidence for the key region queries: no SCAN on the
    # big tables (all plans use covering/indexed SEARCH).
    conn = MD.connect(mpath)
    plans = conn.execute(
        "EXPLAIN QUERY PLAN SELECT endpoint_a, endpoint_b FROM adjudications"
        " WHERE status='active' AND kind='same' AND"
        " (endpoint_a IN ('indicator--A') OR endpoint_b IN ('indicator--A'))"
    ).fetchall()
    plan_text = " | ".join(r[3] for r in plans)
    check("region BFS query plan uses indexes, no SCAN",
          "SCAN adjudications" not in plan_text and "SEARCH" in plan_text,
          plan_text)
    conn.close()


def main():
    work = tempfile.mkdtemp(prefix="sg-master-")
    try:
        test_main_scenario(work)
        test_orientation_and_batch_rules(work)
        test_same_priority_order(work)
        test_blocking_evidence_switch(work)
        test_self_loop(work)
        test_empty_diff_and_replace(work)
        test_concurrent_writers(work)
        test_crash_and_resend(work)
        test_relationship_filtering(work)
        test_scale_access_scope(work)
        print(f"\n{PASS} passed, {FAIL} failed")
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
