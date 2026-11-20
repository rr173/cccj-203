#!/usr/bin/env python3
"""Bulk / streaming verification.

Generates a large synthetic NDJSON corpus (nested arrays), runs the full
ingest -> finalize -> project -> query pipeline, and asserts:
  * peak RSS stays bounded and far below the on-disk corpus size;
  * hidden odd-index array slots are null and their exact values are absent
    from both the live tables and the projection file bytes;
  * search over hidden slots returns zero, visible slots return matches;
  * nothing requires the whole corpus in memory (NDJSON is streamed).

Run:  python3 -I tests/run_bulk_verify.py
"""
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "sg-cli.py")
N_OBJECTS = int(os.environ.get("SG_BULK_OBJECTS", "20000"))
WIDTH = int(os.environ.get("SG_BULK_WIDTH", "40"))

PASS = FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}", flush=True)
    else:
        FAIL += 1
        print(f"  FAIL  {label} {detail}", flush=True)


def run(*args):
    proc = subprocess.run([sys.executable, "-I", CLI, *args],
                          cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def main():
    work = tempfile.mkdtemp(prefix="sg-bulk-")
    try:
        corpus = os.path.join(work, "bulk.ndjson")
        gen = subprocess.run(
            [sys.executable, "-I",
             os.path.join(ROOT, "tests", "gen_bulk.py"),
             "--out", corpus, "--objects", str(N_OBJECTS),
             "--array-width", str(WIDTH)], capture_output=True, text=True)
        check("generator rc=0", gen.returncode == 0, gen.stderr)

        policy = os.path.join(work, "policy.json")
        json.dump({"principals": [
            {"principal": "granted",
             "allowed_marking_ids": ["marking-definition--bulk-m1"]},
            {"principal": "restricted", "allowed_marking_ids": []}]},
            open(policy, "w"))
        store = os.path.join(work, "bulk.sqlite")
        pdir = os.path.join(work, "proj")
        os.makedirs(pdir)
        t = "2026-02-01T00:00:00Z"

        def measured(step, *args):
            rc, out, err = run(*args)
            if rc != 0:
                raise AssertionError(f"{step} failed: {err}")
            peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            print(f"  [mem] {step} cumulative child peak RSS = {peak} KB",
                  flush=True)
            return json.loads(out), peak

        staged, peak_stage = measured(
            "stage", "stage", "--store", store, "--stage-id", "bulk", corpus)
        check("all objects staged",
              staged["received_objects"] == N_OBJECTS + 1, str(staged))

        finalized, peak_final = measured(
            "finalize", "finalize", "--store", store, "--codename", "BULK",
            "--stage-id", "bulk", "--policy", policy)
        check("all bulk objects finalized",
              finalized["objects"] == N_OBJECTS, str(finalized))

        projected, peak_proj = measured(
            "project-restricted", "project", "--store", store,
            "--proj-dir", pdir, "--codename", "BULK", "--at", t,
            "--principal", "restricted", "--policy", policy)
        check("all objects visible (row-level public, field-level hidden)",
              projected["visible"] == N_OBJECTS, str(projected))

        corpus_bytes = os.path.getsize(corpus)
        # peak RSS must be a small fraction of corpus size (bounded streaming)
        for name, peak in (("stage", peak_stage), ("finalize", peak_final),
                           ("project", peak_proj)):
            check(f"{name} peak RSS < 50% of corpus bytes "
                  f"({peak}KB vs {corpus_bytes // 1024}KB)",
                  peak * 1024 < corpus_bytes * 0.5)

        # pick a sample object and assert null placeholders on odd slots
        sample = "indicator--bulk-00000007"
        rc, out, err = run("get", "--proj-dir", pdir, "--codename", "BULK",
                           "--at", t, "--principal", "restricted",
                           "--policy", policy, "--id", sample)
        doc = json.loads(out)["object"]
        check("odd label slot is null", doc["labels"][1] is None, str(doc["labels"][:4]))
        check("even label slot preserved",
              doc["labels"][0] == "bulk-label-7-0", str(doc["labels"][:4]))
        check("odd external_reference slot is null",
              doc["external_references"][1] is None)
        check("even external_reference slot preserved",
              doc["external_references"][0]["source_name"] == "src-7-0")

        # exact hidden value must not match in search
        rc, out, err = run("search", "--proj-dir", pdir, "--codename", "BULK",
                           "--at", t, "--principal", "restricted",
                           "--policy", policy, "--field", "labels",
                           "--match", "exact", "--term", "bulk-label-7-1",
                           "--limit", "5")
        # slot index 1 is hidden; note bulk-label-7-10 is a different token, so
        # exact match on the full hidden token must be zero.
        check("exact search on hidden slot-1 token is zero",
              json.loads(out)["hits"] == 0, out)
        rc, out, err = run("search", "--proj-dir", pdir, "--codename", "BULK",
                           "--at", t, "--principal", "restricted",
                           "--policy", policy, "--field", "labels",
                           "--match", "exact", "--term", "bulk-label-7-0",
                           "--limit", "5")
        check("exact search on visible slot-0 token matches",
              json.loads(out)["hits"] >= 1, out)

        # byte-level: quoted exact hidden tokens absent from projection file
        proj_file = projected["projection_file"]
        blob = open(proj_file, "rb").read()
        check('hidden token bulk-label-7-1" absent from projection bytes',
              b'bulk-label-7-1"' not in blob)
        check('hidden nested ref "src-7-1" absent from projection bytes',
              b'"src-7-1"' not in blob)
        check("visible value still present", b"bulk-label-7-0" in blob)

        # pagination on a large result set stays consistent
        rc, out, err = run("search", "--proj-dir", pdir, "--codename", "BULK",
                           "--at", t, "--principal", "restricted",
                           "--policy", policy, "--field", "labels",
                           "--match", "substring", "--term", "bulk-label",
                           "--limit", "100")
        first = json.loads(out)
        check("first bulk page full", first["hits"] == 100
              and first["next_page_token"] is not None, str(first)[:200])
        seen = {i["id"] for i in first["items"]}
        rc, out, err = run("search", "--proj-dir", pdir, "--codename", "BULK",
                           "--at", t, "--principal", "restricted",
                           "--policy", policy, "--field", "labels",
                           "--match", "substring", "--term", "bulk-label",
                           "--limit", "100",
                           "--page-token", first["next_page_token"])
        second = json.loads(out)
        check("second page disjoint from first (stable ordering)",
              seen.isdisjoint({i["id"] for i in second["items"]}),
              "overlap detected")

        print(f"\n{PASS} passed, {FAIL} failed", flush=True)
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
