"""Command line interface for the STIX gate.

Every error message is content-free: restricted values live only in the
protected source store and are printed solely by an explicit administrator
``--reveal`` action on that store.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

from .util import SGError, parse_time, dt_to_key
from . import store as S
from . import projection as P
from . import markings as M
from . import master as MD


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _load_policy_doc(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return doc


def _emit(obj, as_lines=False):
    if as_lines and isinstance(obj, list):
        for item in obj:
            sys.stdout.write(json.dumps(item, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def _fail(exc: SGError):
    sys.stderr.write(json.dumps(exc.to_dict(), ensure_ascii=False) + "\n")
    return 2


# --------------------------------------------------------------- commands ----

def cmd_stage(args):
    conn = S.connect(args.store)
    n = S.stage_bundle(conn, args.stage_id, args.bundle, _now())
    conn.close()
    _emit({"stage_id": args.stage_id, "received_objects": n, "status": "staged"})


def cmd_finalize(args):
    conn = S.connect(args.store)
    expected = None
    if args.policy:
        doc = _load_policy_doc(args.policy)
        policy = M.load_policy(doc)
        expected = set()
        for allowed in policy["principals"].values():
            expected |= allowed
    stats = S.finalize(conn, args.codename, args.stage_id, _now(),
                       expected_marking_ids=expected)
    conn.close()
    _emit(stats)


def cmd_project(args):
    doc = _load_policy_doc(args.policy)
    policy = M.load_policy(doc)
    digest = M.policy_digest(doc)
    t_key = dt_to_key(parse_time(args.at))
    src = S.connect(args.store)
    if not src.execute("SELECT 1 FROM collections WHERE codename=?",
                       (args.codename,)).fetchone():
        raise SGError("unknown-collection", "collection codename does not exist")
    path = P.projection_path(args.proj_dir, args.codename, t_key, args.principal, digest)
    stats = P.build_projection(src, path, args.codename, args.at,
                               args.principal, policy, digest)
    src.close()
    stats.update({"projection_file": path, "principal": args.principal,
                  "policy_digest": digest, "at": args.at})
    _emit(stats)


def _open_proj_for_query(args):
    doc = _load_policy_doc(args.policy)
    M.load_policy(doc)  # validate
    digest = M.policy_digest(doc)
    t_key = dt_to_key(parse_time(args.at))
    path = P.projection_path(args.proj_dir, args.codename, t_key, args.principal, digest)
    conn = P.open_projection(path)
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    if meta.get("principal") != args.principal or meta.get("policy_digest") != digest \
            or meta.get("t_key") != str(t_key) or meta.get("codename") != args.codename:
        raise SGError("projection-context-mismatch",
                      "projection file identity does not match request")
    return conn


def cmd_search(args):
    conn = _open_proj_for_query(args)
    result = P.search(conn, args.field, args.match, args.term,
                      args.limit, args.page_token)
    conn.close()
    _emit(result)


def cmd_get(args):
    conn = _open_proj_for_query(args)
    obj = P.get_object(conn, args.id)
    conn.close()
    if obj is None:
        _emit({"id": args.id, "visible": False, "object": None})
    else:
        obj["id"] = args.id
        obj["visible"] = True
        _emit(obj)


def cmd_references(args):
    conn = _open_proj_for_query(args)
    result = P.references(conn, args.id, args.direction)
    conn.close()
    _emit(result)


def cmd_diagnostics(args):
    """Administrator-only failure locations. No object bodies by default."""
    conn = S.connect(args.store)
    rows = S.diagnostics(conn, args.codename)
    out = []
    for r in rows:
        item = {"object_id": r["obj_id"], "modified_key": r["modified_key"],
                "kind": r["kind"], "detail": r["detail"],
                "body_available": bool(r["has_body"])}
        if args.reveal:
            raw = S.get_raw(conn, args.codename, r["obj_id"], r["modified_key"])
            item["revealed_body"] = json.loads(raw["raw_json"]) if raw else None
        out.append(item)
    conn.close()
    _emit({"codename": args.codename, "admin": True, "reveal": bool(args.reveal),
           "failures": out})


def cmd_source(args):
    """Administrator raw retrieval from the protected store only."""
    if not args.reveal:
        raise SGError("reveal-required",
                      "reading protected source bodies requires an explicit --reveal flag")
    conn = S.connect(args.store)
    row = S.get_raw(conn, args.codename, args.id)
    conn.close()
    if not row:
        raise SGError("not-found", "no such object in the protected store")
    _emit({"admin": True, "object": json.loads(row["raw_json"])})


def cmd_export(args):
    """Atomically export a projection as a self-contained, reopenable package."""
    src_conn = P.open_projection(args.projection)
    # verify integrity of the source projection first
    ok = src_conn.execute("PRAGMA integrity_check").fetchone()[0]
    if ok != "ok":
        src_conn.close()
        raise SGError("integrity-failure", "source projection fails integrity check")
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sqlite.tmp",
                                        dir=os.path.dirname(os.path.abspath(args.output)))
    os.close(tmp_fd)
    try:
        out = sqlite3.connect(tmp_path)
        with out:
            src_conn.backup(out)  # consistent snapshot copy
        out.close()
        check = sqlite3.connect(tmp_path)
        if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            check.close()
            raise SGError("integrity-failure", "exported package fails integrity check")
        nobj = check.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        check.close()
        os.replace(tmp_path, args.output)  # atomic: no half package on failure
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
    finally:
        src_conn.close()
    _emit({"exported": args.output, "objects": nobj, "status": "sealed"})


def cmd_reopen(args):
    """Reopen an exported package read-only and run a query against it."""
    conn = sqlite3.connect(f"file:{args.package}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    if args.action == "search":
        result = P.search(conn, args.field, args.match, args.term, args.limit,
                          args.page_token)
    elif args.action == "get":
        result = P.get_object(conn, args.id) or {"id": args.id, "visible": False,
                                                 "object": None}
    elif args.action == "references":
        result = P.references(conn, args.id, args.direction)
    else:
        raise SGError("unsupported-action", "unknown reopen action")
    result["package_meta"] = meta
    conn.close()
    _emit(result)


def cmd_collections(args):
    conn = S.connect(args.store)
    rows = conn.execute("SELECT codename, finalized_at, stage_list FROM collections").fetchall()
    conn.close()
    _emit([{"codename": r["codename"], "finalized_at": r["finalized_at"],
            "stages": json.loads(r["stage_list"])} for r in rows])


# ----------------------------------------------------------- master warehouse ----

def cmd_master_build(args):
    stats = MD.build_master(args.package, args.master)
    stats["package_context"] = MD.package_context(args.master)
    _emit(stats)


def cmd_master_apply(args):
    with open(args.batch, "rb") as fh:
        raw = fh.read()
    receipt = MD.apply_batch(args.master, raw)
    if args.quiet:
        _emit({"batch_id": receipt["batch_id"],
               "published_revision": receipt["published_revision"],
               "deduplicated": receipt["deduplicated"]})
    else:
        _emit(receipt)


def cmd_master_read(args):
    snapshot = MD.read_all(args.master)
    if args.table:
        if args.table not in snapshot["tables"]:
            raise SGError("unknown-table", "no such logical table")
        if args.jsonl:
            for row in snapshot["tables"][args.table]:
                sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")
        else:
            _emit({"revision": snapshot["revision"],
                   "table": args.table,
                   "rows": snapshot["tables"][args.table]})
        return
    if args.jsonl:
        sys.stdout.write(json.dumps(
            {"type": "snapshot_header", "revision": snapshot["revision"]},
            ensure_ascii=False) + "\n")
        for table_name in MD.TABLE_ORDER:
            for row in snapshot["tables"][table_name]:
                sys.stdout.write(json.dumps(
                    {"type": "row", "table": table_name, "row": row},
                    ensure_ascii=False) + "\n")
    else:
        _emit(snapshot)


def cmd_master_changes(args):
    for item in MD.read_changes(args.master, args.from_revision, args.to_revision):
        sys.stdout.write(json.dumps(item, ensure_ascii=False) + "\n")


def cmd_master_revisions(args):
    _emit(MD.list_revisions(args.master))


def cmd_master_context(args):
    _emit(MD.package_context(args.master))


# ------------------------------------------------------------------- parser ----

def build_parser():
    p = argparse.ArgumentParser(prog="sg", description="Versioned STIX 2.1 analysis gate")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("stage", help="receive a complete bundle set into a stage")
    sp.add_argument("--store", required=True)
    sp.add_argument("--stage-id", required=True)
    sp.add_argument("bundle", nargs="+")
    sp.set_defaults(func=cmd_stage)

    sp = sub.add_parser("finalize", help="publish an immutable collection codename")
    sp.add_argument("--store", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--stage-id", nargs="+", required=True)
    sp.add_argument("--policy")
    sp.set_defaults(func=cmd_finalize)

    sp = sub.add_parser("collections", help="list published collections")
    sp.add_argument("--store", required=True)
    sp.set_defaults(func=cmd_collections)

    sp = sub.add_parser("project", help="build an isolated projection for a principal at time t")
    sp.add_argument("--store", required=True)
    sp.add_argument("--proj-dir", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--at", required=True)
    sp.add_argument("--principal", required=True)
    sp.add_argument("--policy", required=True)
    sp.set_defaults(func=cmd_project)

    sp = sub.add_parser("search", help="search inside an authorized projection")
    sp.add_argument("--proj-dir", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--at", required=True)
    sp.add_argument("--principal", required=True)
    sp.add_argument("--policy", required=True)
    sp.add_argument("--field", required=True, choices=list(P.SEARCH_FIELDS) + ["any"])
    sp.add_argument("--match", required=True, choices=["exact", "substring"])
    sp.add_argument("--term", required=True)
    sp.add_argument("--limit", type=int, default=20)
    sp.add_argument("--page-token", default=None)
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("get", help="fetch one projected object by id")
    sp.add_argument("--proj-dir", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--at", required=True)
    sp.add_argument("--principal", required=True)
    sp.add_argument("--policy", required=True)
    sp.add_argument("--id", required=True)
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("references", help="upstream/downstream relationship edges")
    sp.add_argument("--proj-dir", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--at", required=True)
    sp.add_argument("--principal", required=True)
    sp.add_argument("--policy", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--direction", default="both")
    sp.set_defaults(func=cmd_references)

    sp = sub.add_parser("diagnostics", help="admin failure locations (no bodies by default)")
    sp.add_argument("--store", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--reveal", action="store_true")
    sp.set_defaults(func=cmd_diagnostics)

    sp = sub.add_parser("source", help="admin raw source read (requires --reveal)")
    sp.add_argument("--store", required=True)
    sp.add_argument("--codename", required=True)
    sp.add_argument("--id", required=True)
    sp.add_argument("--reveal", action="store_true")
    sp.set_defaults(func=cmd_source)

    sp = sub.add_parser("export", help="export a projection to a standalone SQLite package")
    sp.add_argument("--projection", required=True)
    sp.add_argument("--output", required=True)
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("reopen", help="reopen an exported package read-only")
    sp.add_argument("--package", required=True)
    sp.add_argument("action", choices=["search", "get", "references"])
    sp.add_argument("--field", default="any")
    sp.add_argument("--match", default="exact")
    sp.add_argument("--term", default="")
    sp.add_argument("--limit", type=int, default=20)
    sp.add_argument("--page-token", default=None)
    sp.add_argument("--id")
    sp.add_argument("--direction", default="both")
    sp.set_defaults(func=cmd_reopen)

    # --------------------------------------------------- master-data warehouse ----
    sp = sub.add_parser("master-build",
                        help="bind one exported projection package into a revision-0 master warehouse")
    sp.add_argument("--package", required=True)
    sp.add_argument("--master", required=True)
    sp.set_defaults(func=cmd_master_build)

    sp = sub.add_parser("master-apply",
                        help="apply one validated adjudication batch as a new revision")
    sp.add_argument("--master", required=True)
    sp.add_argument("--batch", required=True)
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_master_apply)

    sp = sub.add_parser("master-read",
                        help="read the four logical tables at one committed revision")
    sp.add_argument("--master", required=True)
    sp.add_argument("--table", choices=list(MD.TABLE_ORDER),
                    help="read one logical table instead of the whole snapshot")
    sp.add_argument("--jsonl", action="store_true",
                    help="emit JSONL instead of one JSON document")
    sp.set_defaults(func=cmd_master_read)

    sp = sub.add_parser("master-changes",
                        help="stream ordered JSONL change records for a revision range")
    sp.add_argument("--master", required=True)
    sp.add_argument("--from", dest="from_revision", required=True, type=int)
    sp.add_argument("--to", dest="to_revision", required=True, type=int)
    sp.set_defaults(func=cmd_master_changes)

    sp = sub.add_parser("master-revisions", help="list committed revisions")
    sp.add_argument("--master", required=True)
    sp.set_defaults(func=cmd_master_revisions)

    sp = sub.add_parser("master-context",
                        help="show the sealed package summary and context bound to this warehouse")
    sp.add_argument("--master", required=True)
    sp.set_defaults(func=cmd_master_context)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except SGError as exc:
        return _fail(exc)
    except FileNotFoundError as exc:
        return _fail(SGError("file-not-found", "a required input file is missing"))
    except json.JSONDecodeError:
        return _fail(SGError("invalid-json", "input document is not valid JSON"))
    except sqlite3.Error:
        # Never surface raw SQLite text: it can embed file paths or row data.
        return _fail(SGError("storage-error", "the SQLite store could not complete the operation"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
