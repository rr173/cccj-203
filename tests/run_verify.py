#!/usr/bin/env python3
"""Independent end-to-end verification for the STIX gate.

A standalone checker: it drives the CLI as subprocesses (so it also proves the
documented shell commands work) and asserts hand-written expectations. It does
not import the gate's decision code to decide expected values — expectations
are literal values written below.

Run:  python3 -I tests/run_verify.py
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

PASS, FAIL = 0, 0


def run(*args):
    proc = subprocess.run(
        [sys.executable, "-I", CLI, *args],
        cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}", flush=True)
    else:
        FAIL += 1
        print(f"  FAIL  {label}  {detail}", flush=True)


def jload(text):
    return json.loads(text)


def main():
    work = tempfile.mkdtemp(prefix="sg-verify-")
    store = os.path.join(work, "source.sqlite")
    pdir = os.path.join(work, "proj")
    os.makedirs(pdir)
    policy = os.path.join(DATA, "policy.json")
    t = "2026-02-01T00:00:00Z"

    # ---- ingestion ----------------------------------------------------
    rc, out, err = run("stage", "--store", store, "--stage-id", "s1",
                       os.path.join(DATA, "00_markings.json"),
                       os.path.join(DATA, "01_main.json"),
                       os.path.join(DATA, "02_versions.json"),
                       os.path.join(DATA, "03_failures.json"))
    check("stage rc=0", rc == 0, err)
    check("stage received 31", jload(out)["received_objects"] == 31, out)

    rc, out, err = run("stage", "--store", store, "--stage-id", "s1",
                       os.path.join(DATA, "01_main.json"))
    check("duplicate stage rejected", rc == 2, err)

    rc, out, err = run("finalize", "--store", store, "--codename", "C1",
                       "--stage-id", "s1", "--policy", policy)
    check("finalize rc=0", rc == 0, err)
    stats = jload(out)
    check("3 globally blocked objects", stats["blocked"] == 3, out)
    check("1 same-time conflict bucket", stats["conflicts"] == 1, out)
    check("2 revoked versions", stats["revoked"] == 2, out)
    check("1 unsupported source type", stats["unsupported"] == 1, out)

    rc, out, err = run("finalize", "--store", store, "--codename", "C1",
                       "--stage-id", "s1", "--policy", policy)
    check("codename immutable (republish rejected)", rc == 2, err)

    rc, out, err = run("stage", "--store", store, "--stage-id", "s2",
                       os.path.join(DATA, "00_markings.json"),
                       os.path.join(DATA, "04_marking_conflict.json"),
                       os.path.join(DATA, "01_main.json"))
    check("stage s2 rc=0", rc == 0, err)
    rc, out, err = run("finalize", "--store", store, "--codename", "C2",
                       "--stage-id", "s2", "--policy", policy)
    check("C2 records conflicted M1",
          jload(out)["conflicted_markings"] == ["marking-definition--m1"], out)

    def proj(codename, principal, at=t):
        rc, out, err = run("project", "--store", store, "--proj-dir", pdir,
                           "--codename", codename, "--at", at,
                           "--principal", principal, "--policy", policy)
        # re-projecting an identical (codename,t,principal,digest) is refused
        # by design; that is fine for read-only verification.
        if rc != 0 and "projection-exists" not in err:
            raise AssertionError(f"project failed: {err}")
        return jload(out) if rc == 0 else {}

    def get_obj(principal, oid, at=t):
        proj("C1", principal, at)
        rc, out, err = run("get", "--proj-dir", pdir, "--codename", "C1",
                           "--at", at, "--principal", principal,
                           "--policy", policy, "--id", oid)
        if rc != 0:
            raise AssertionError(f"get failed rc={rc} {err}")
        return jload(out)

    def search(principal, field, match, term, token=None, limit=20):
        args = ["search", "--proj-dir", pdir, "--codename", "C1", "--at", t,
                "--principal", principal, "--policy", policy,
                "--field", field, "--match", match, "--term", term,
                "--limit", str(limit)]
        if token:
            args += ["--page-token", token]
        rc, out, err = run(*args)
        if rc != 0:
            raise AssertionError(f"search failed: {err}")
        return jload(out)

    for p in ("alice", "bob", "carol"):
        proj("C1", p)

    print("\n[hand-written projection matrix for indicator--O]")
    a = get_obj("alice", "indicator--O")
    check("alice sees secret S (M1 granted)",
          a["object"]["labels"][1] == "SECRET-LABEL-S-M1", out)
    check("alice description removed (M2 missing)",
          "description" not in a["object"], out)
    check("alice keeps public index 2 T",
          a["object"]["labels"][2] == "public-word-T", out)

    b = get_obj("bob", "indicator--O")
    check("bob sees description (M2 granted)",
          b["object"].get("description") == "SECRET-DESCRIPTION-M2", out)
    check("bob sees secret S",
          b["object"]["labels"][1] == "SECRET-LABEL-S-M1", out)
    check("bob has no redaction on O", b["redacted"] == [], out)

    c = get_obj("carol", "indicator--O")
    check("carol labels[1] is null placeholder",
          c["object"]["labels"][1] is None, out)
    check("carol labels[2] still T (index preserved)",
          c["object"]["labels"][2] == "public-word-T", out)
    check("carol description removed", "description" not in c["object"], out)
    check("carol redacted lists labels.[1]", "labels.[1]" in c["redacted"], out)

    print("\n[stacked markings: M1 and M2 on same field]")
    ov = get_obj("alice", "indicator--OV")
    check("alice holding only M1 still cannot see name (M2 also required)",
          "name" not in ov["object"], out)
    ovb = get_obj("bob", "indicator--OV")
    check("bob holding M1+M2 sees name",
          ovb["object"].get("name") == "STACKED-MARKING-NAME", out)

    print("\n[search isolation and counts]")
    check("alice can search secret S, 1 hit",
          search("alice", "labels", "exact", "SECRET-LABEL-S-M1")["hits"] == 1)
    check("carol search S exact -> 0",
          search("carol", "labels", "exact", "SECRET-LABEL-S-M1")["hits"] == 0)
    check("carol search S substring -> 0",
          search("carol", "labels", "substring", "SECRET")["hits"] == 0)
    check("carol search T -> 1",
          search("carol", "labels", "exact", "public-word-T")["hits"] == 1)
    check("null is not the string 'null'",
          search("carol", "labels", "exact", "null")["hits"] == 0)
    check("hidden description cannot be searched",
          search("carol", "description", "substring",
                 "SECRET-DESCRIPTION")["hits"] == 0)

    print("\n[relationships: hidden endpoint suppresses the edge]")
    rc, out, err = run("references", "--proj-dir", pdir, "--codename", "C1",
                       "--at", t, "--principal", "alice", "--policy", policy,
                       "--id", "indicator--O")
    refs = jload(out)
    check("alice edge to M3-only target suppressed",
          refs["downstream_count"] == 0 and refs["upstream_count"] == 0, out)
    rc, out, err = run("references", "--proj-dir", pdir, "--codename", "C1",
                       "--at", t, "--principal", "carol", "--policy", policy,
                       "--id", "malware--T")
    hidden = jload(out)
    check("hidden endpoint identity not echoed",
          hidden["visible"] is False and hidden["downstream"] == [], out)
    rc, out, err = run("references", "--proj-dir", pdir, "--codename", "C1",
                       "--at", t, "--principal", "carol", "--policy", policy,
                       "--id", "indicator--NEST")
    edge = jload(out)
    check("public edge visible when both endpoints visible",
          edge["downstream_count"] == 1
          and edge["downstream"][0]["target_id"] == "malware--PUBLIC-MW", out)

    print("\n[time views, conflict, revoke, future versions]")
    check("V at 01-15 is v1",
          get_obj("carol", "indicator--V", "2026-01-15T00:00:00Z"
                  )["object"]["name"] == "V-v1")
    check("V at 01-25 is v2",
          get_obj("carol", "indicator--V", "2026-01-25T00:00:00Z"
                  )["object"]["name"] == "V-v2")
    check("future v3 not visible at 02-01, still v2",
          get_obj("carol", "indicator--V", t)["object"]["name"] == "V-v2")
    check("v3 visible after its modified time",
          get_obj("carol", "indicator--V", "2026-03-01T00:00:00Z"
                  )["object"]["name"] == "V-v3-future")

    check("K unavailable during same-time conflict",
          get_obj("carol", "indicator--K", "2026-01-16T00:00:00Z"
                  ).get("object") is None)
    check("K old version still readable before conflict",
          get_obj("carol", "indicator--K", "2026-01-12T00:00:00Z"
                  )["object"]["name"] == "K-before-conflict")
    check("K recovers once a newer consistent version exists",
          get_obj("carol", "indicator--K", "2026-01-26T00:00:00Z"
                  )["object"]["name"] == "K-resolved-newer-version")

    check("X exact pre-revoke history readable",
          get_obj("carol", "indicator--X", "2026-01-10T00:00:00Z"
                  )["object"]["name"] == "X-alive")
    check("X revoked view unavailable",
          get_obj("carol", "indicator--X", "2026-01-21T00:00:00Z"
                  ).get("object") is None)

    check("Y plain revoke unavailable",
          get_obj("carol", "indicator--Y", "2026-01-21T00:00:00Z"
                  ).get("object") is None)
    check("Y revoked=false afterwards is a business conflict",
          get_obj("carol", "indicator--Y", "2026-02-06T00:00:00Z"
                  ).get("object") is None)

    check("created>modified object never projected",
          get_obj("carol", "indicator--BADTIME").get("object") is None)

    print("\n[invalid selector / unknown marking / identity-field hide]")
    for oid in ("indicator--BADSEL", "indicator--UNKMARK", "indicator--IDHIDE",
                "indicator--OBJREF"):
        check(f"{oid} absent from normal projection",
              get_obj("alice", oid).get("object") is None, out)

    print("\n[diagnostics never leak bodies without explicit reveal]")
    rc, out, err = run("diagnostics", "--store", store, "--codename", "C1")
    diag = jload(out)
    check("diagnostics lists failure locations", len(diag["failures"]) >= 5, out)
    check("no revealed_body field by default",
          all("revealed_body" not in f for f in diag["failures"]), out)
    check("no secret string in plain diagnostics", "SECRET" not in out, out)
    rc, out, err = run("source", "--store", store, "--codename", "C1",
                       "--id", "indicator--BADSEL")
    check("source read without --reveal refused", rc == 2, err)
    rc, out, err = run("source", "--store", store, "--codename", "C1",
                       "--id", "indicator--BADSEL", "--reveal")
    check("admin --reveal returns raw body",
          rc == 0 and jload(out)["object"]["id"] == "indicator--BADSEL", err)

    print("\n[pagination tokens bind context]")
    page1 = search("carol", "any", "substring", "public", limit=1)
    check("page 1 has a next token", page1["next_page_token"] is not None, out)
    tok = page1["next_page_token"]
    page2 = search("carol", "any", "substring", "public", token=tok, limit=1)
    check("page 2 advances to a different object",
          page2["items"][0]["id"] != page1["items"][0]["id"], out)
    rc, out, err = run("search", "--proj-dir", pdir, "--codename", "C1",
                       "--at", t, "--principal", "alice", "--policy", policy,
                       "--field", "any", "--match", "substring", "--term",
                       "public", "--limit", "1", "--page-token", tok)
    check("token reused across principals rejected", rc == 2, err)
    rc, out, err = run("search", "--proj-dir", pdir, "--codename", "C1",
                       "--at", t, "--principal", "carol", "--policy", policy,
                       "--field", "any", "--match", "substring", "--term",
                       "OTHER", "--limit", "1", "--page-token", tok)
    check("token with changed query conditions rejected", rc == 2, err)

    print("\n[policy change changes the digest and isolates tokens]")
    v2_path = os.path.join(work, "policy_v2.json")
    pdoc = json.load(open(policy))
    for e in pdoc["principals"]:
        if e["principal"] == "carol":
            e["allowed_marking_ids"] = ["marking-definition--m1"]
    json.dump(pdoc, open(v2_path, "w"))
    rc, out, err = run("project", "--store", store, "--proj-dir", pdir,
                       "--codename", "C1", "--at", t, "--principal", "carol",
                       "--policy", v2_path)
    check("new policy produces a new digest projection", rc == 0, err)
    rc, out, err = run("search", "--proj-dir", pdir, "--codename", "C1",
                       "--at", t, "--principal", "carol", "--policy", v2_path,
                       "--field", "any", "--match", "substring", "--term",
                       "public", "--limit", "1", "--page-token", tok)
    check("old token rejected under new policy digest", rc == 2, err)

    print("\n[export and read-only reopen]")
    from sg.markings import policy_digest
    from sg.util import time_key
    from sg.projection import projection_path
    orig_digest = policy_digest(json.load(open(policy)))
    carol_proj = projection_path(pdir, "C1", time_key(t), "carol", orig_digest)
    check("carol projection file exists", os.path.exists(carol_proj))
    export_path = os.path.join(work, "export.sqlite")
    rc, out, err = run("export", "--projection", carol_proj,
                       "--output", export_path)
    check("export rc=0", rc == 0, err)
    rc, out, err = run("reopen", "--package", export_path, "search",
                       "--field", "labels", "--match", "exact",
                       "--term", "public-word-T")
    reopened = jload(out)
    check("reopened package search works", reopened["hits"] == 1, out)
    check("reopened package carries principal meta",
          reopened["package_meta"]["principal"] == "carol", out)
    rc, out, err = run("reopen", "--package", export_path, "search",
                       "--field", "labels", "--match", "exact",
                       "--term", "SECRET-LABEL-S-M1")
    check("reopened package hides restricted value (0 hits)",
          jload(out)["hits"] == 0, err)

    print("\n[byte-level: restricted values absent from projection/export]")
    secret_bytes = ["SECRET-LABEL-S-M1", "SECRET-DESCRIPTION-M2",
                    "malware-T-M3-only", "n1-secret"]
    for path in (carol_proj, export_path):
        blob = open(path, "rb").read()
        for s in secret_bytes:
            check(f"{os.path.basename(path)} excludes {s}",
                  s.encode() not in blob)
    check("protected source still holds restricted body",
          b"SECRET-LABEL-S-M1" in open(store, "rb").read())

    print("\n[conflicted marking definition withdraws referencing objects]")
    rc, out, err = run("project", "--store", store, "--proj-dir", pdir,
                       "--codename", "C2", "--at", t, "--principal", "alice",
                       "--policy", policy)
    check("C2 projection builds despite conflicted marking", rc == 0, err)
    rc, out, err = run("get", "--proj-dir", pdir, "--codename", "C2",
                       "--at", t, "--principal", "alice", "--policy", policy,
                       "--id", "indicator--O")
    check("O unavailable when its M1 marking definition is conflicted",
          jload(out).get("object") is None, out)

    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(2)
