#!/usr/bin/env python3
"""Unit checks for selector parsing, path coverage and redaction rendering.

These exercise the pure rules directly (no SQLite), including malformed
selectors and the order-independence of overlapping parent/child markings.

Run:  python3 -I tests/run_unit_verify.py
"""
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sg.selectors import split_selector, validate_selector, is_covered  # noqa: E402
from sg.redact import redact_object  # noqa: E402
from sg.util import SGError  # noqa: E402

PASS = FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} {detail}")


def expect_error(label, fn):
    try:
        fn()
        check(label, False, "no error raised")
    except SGError as exc:
        check(label, exc.code == "invalid_selector", str(exc))


def main():
    # tokenization per STIX 2.1 bracket syntax
    check("labels.[1] -> ['labels',1]",
          split_selector("labels.[1]") == ["labels", 1])
    check("external_references.[0].source_name tokens",
          split_selector("external_references.[0].source_name")
          == ["external_references", 0, "source_name"])
    check("plain property path", split_selector("name") == ["name"])
    check("nested index then property",
          split_selector("a.[2].b.[0]") == ["a", 2, "b", 0])

    expect_error("empty selector rejected", lambda: split_selector(""))
    expect_error("dangling bracket rejected", lambda: split_selector("labels.[1"))
    expect_error("negative index rejected", lambda: split_selector("labels.[-1]"))
    expect_error("leading index rejected", lambda: split_selector("[0]"))
    expect_error("non-numeric index rejected", lambda: split_selector("labels.[x]"))

    obj = {
        "labels": ["a", "b", "c"],
        "external_references": [{"source_name": "s0"}, {"source_name": "s1"}],
        "nested": {"deep": {"leaf": 1}},
    }
    check("existing array index validates",
          validate_selector(obj, "labels.[2]") == ["labels", 2])
    expect_error("out-of-range index rejected",
                 lambda: validate_selector(obj, "labels.[9]"))
    expect_error("missing property rejected",
                 lambda: validate_selector(obj, "nested.absent.leaf"))
    check("deep existing path validates",
          validate_selector(obj, "nested.deep.leaf")
          == ["nested", "deep", "leaf"])

    # parent path covers whole subtree regardless of declaration order
    parent = ["nested"]
    child = ["nested", "deep", "leaf"]
    check("parent covers child", is_covered(child, parent))
    check("child does not cover parent", not is_covered(parent, child))
    check("equal paths cover each other", is_covered(child, child))
    check("array element covered by its array parent",
          is_covered(["labels", 1], ["labels"]))

    # redaction: property deleted, array element null, index preserved
    target = {
        "id": "indicator--x", "type": "indicator",
        "labels": ["keep", "secret", "keep2"],
        "description": "hidden",
        "external_references": [
            {"source_name": "pub"}, {"source_name": "sec"}],
    }
    blocked = [["description"], ["labels", 1], ["external_references", 1]]
    proj, redacted = redact_object(target, blocked)
    check("hidden property deleted", "description" not in proj)
    check("array null placeholder keeps index",
          proj["labels"] == ["keep", None, "keep2"])
    check("nested array element null placeholder",
          proj["external_references"] == [{"source_name": "pub"}, None])
    check("redacted paths reported",
          set(redacted) == {"description", "labels.[1]",
                            "external_references.[1]"})

    # order independence: parent subtree vs child field, both orders
    base = {"id": "i", "type": "indicator",
            "tree": {"child": "v", "sibling": "s"}}
    p1, _ = redact_object(base, [["tree"]])
    p2, _ = redact_object(base, [["tree", "child"], ["tree"]])
    p3, _ = redact_object(base, [["tree"], ["tree", "child"]])
    check("parent-only removes subtree", "tree" not in p1)
    check("parent+child (child first) equals parent removal", "tree" not in p2)
    check("parent+child (parent first) equals parent removal", "tree" not in p3)

    # identity fields never silently disappear via redaction (ingestion rule is
    # enforced upstream; here redact still drops when told, the gate refuses to
    # build such a block at ingest). Confirm render_path formatting.
    from sg.redact import render_path
    check("render_path array formatting",
          render_path(["labels", 1, "x"]) == "labels.[1].x")

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
