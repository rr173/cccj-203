#!/usr/bin/env python3
"""Generate a large synthetic NDJSON STIX stream with nested arrays.

Runs standalone (python -I) and writes one JSON object per line so the gate
can ingest and query it without ever holding the whole corpus in memory.
"""
import argparse
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--objects", type=int, default=20000)
    ap.add_argument("--array-width", type=int, default=40)
    args = ap.parse_args()

    with open(args.out, "w", encoding="utf-8") as fh:
        # marking definition used to hide alternating array slots
        fh.write(json.dumps({
            "type": "marking-definition", "spec_version": "2.1",
            "id": "marking-definition--bulk-m1",
            "created": "2026-01-01T00:00:00.000Z",
            "definition": {"statement": "opaque-bulk-label"},
        }, ensure_ascii=False) + "\n")
        for i in range(args.objects):
            labels = [f"bulk-label-{i}-{j}" for j in range(args.array_width)]
            refs = [{"source_name": f"src-{i}-{j}",
                     "url": f"https://example.test/{i}/{j}"}
                    for j in range(args.array_width)]
            selectors = [f"labels.[{j}]" for j in range(1, args.array_width, 2)]
            selectors += [f"external_references.[{j}]"
                          for j in range(1, args.array_width, 2)]
            obj = {
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--bulk-{i:08d}",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-02-01T00:00:00.000Z",
                "name": f"bulk-name-{i}",
                "description": f"bulk-desc-{i}",
                "pattern": f"[file:name = 'bulk-{i}']",
                "labels": labels,
                "external_references": refs,
                "granular_markings": [
                    {"marking_ref": "marking-definition--bulk-m1",
                     "selectors": selectors},
                ],
            }
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
