#!/usr/bin/env python3
"""Atomicity verification.

Asserts the two no-half-state guarantees:
  1. a failure at the projection publish boundary removes every artifact
     (no sealed-looking .sqlite and no .tmp left behind);
  2. a corrupt/interrupted bundle never publishes a collection codename, and
     finalizing an unknown stage likewise creates nothing.

Run:  python3 -I tests/run_atomic_verify.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "sg-cli.py")
DATA = os.path.join(ROOT, "tests", "data")
sys.path.insert(0, ROOT)

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
    p = subprocess.run([sys.executable, "-I", CLI, *args],
                       cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def main():
    work = tempfile.mkdtemp(prefix="sg-atomic-")
    try:
        store = os.path.join(work, "src.sqlite")
        pdir = os.path.join(work, "proj")
        os.makedirs(pdir)
        policy = os.path.join(DATA, "policy.json")
        t = "2026-02-01T00:00:00Z"

        # healthy C1 collection
        rc, _, err = run("stage", "--store", store, "--stage-id", "s1",
                         os.path.join(DATA, "00_markings.json"),
                         os.path.join(DATA, "01_main.json"),
                         os.path.join(DATA, "02_versions.json"),
                         os.path.join(DATA, "03_failures.json"))
        check("healthy stage", rc == 0, err)
        rc, _, err = run("finalize", "--store", store, "--codename", "C1",
                         "--stage-id", "s1", "--policy", policy)
        check("healthy finalize", rc == 0, err)

        # 1. publish-boundary failure leaves no artifact
        from sg import projection as P, store as S, markings as M
        doc = json.load(open(policy))
        pol = M.load_policy(doc)
        digest = M.policy_digest(doc)
        src = S.connect(store)
        dst = os.path.join(pdir, "broken.sqlite")
        real_replace = os.replace

        def failing_replace(a, b):
            raise RuntimeError("simulated publish failure")

        os.replace = failing_replace
        try:
            try:
                P.build_projection(src, dst, "C1", t, "alice", pol, digest)
                raised = False
            except RuntimeError:
                raised = True
        finally:
            os.replace = real_replace
        check("publish failure propagated", raised)
        leftovers = os.listdir(pdir)
        check("no half-projection and no .tmp after failure",
              leftovers == [], str(leftovers))

        # a normal build afterwards still succeeds and seals
        rc, out, err = run("project", "--store", store, "--proj-dir", pdir,
                           "--codename", "C1", "--at", t,
                           "--principal", "alice", "--policy", policy)
        check("subsequent healthy build succeeds", rc == 0, err)
        sealed = os.listdir(pdir)
        check("exactly one sealed projection present",
              len(sealed) == 1 and sealed[0].endswith(".sqlite"), str(sealed))

        # 2. corrupt bundle: stage fails, no codename ever appears
        bad_dir = os.path.join(work, "bad")
        os.makedirs(bad_dir)
        bad_bundle = os.path.join(bad_dir, "broken.json")
        with open(bad_bundle, "w") as fh:
            fh.write('{"type":"bundle","objects":[\n{"broken":')
        bad_store = os.path.join(bad_dir, "bad.sqlite")
        rc, _, err = run("stage", "--store", bad_store, "--stage-id", "broken",
                         bad_bundle)
        check("corrupt bundle stage rejected", rc == 2, err)
        rc, out, err = run("collections", "--store", bad_store)
        check("no collection codename after corrupt stage",
              rc == 0 and json.loads(out) == [], out)

        # 3. finalize unknown stage creates no codename
        rc, _, err = run("finalize", "--store", store, "--codename", "GHOST",
                         "--stage-id", "never-existed", "--policy", policy)
        check("finalize unknown stage rejected", rc == 2, err)
        rc, out, _ = run("collections", "--store", store)
        check("only C1 exists, no GHOST",
              [c["codename"] for c in json.loads(out)] == ["C1"], out)

        print(f"\n{PASS} passed, {FAIL} failed", flush=True)
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
