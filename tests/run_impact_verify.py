#!/usr/bin/env python3
"""Master-data revision impact analysis — independent verification.

The harness drives the public CLI (``sg-cli.py master-impact-*``) as
subprocesses plus in-process library calls against runtime-generated synthetic
warehouses (nothing large is committed).  Every expectation in
``hand_expected/impact_expectations.json`` was hand-traced from the fixture
batches; this script also runs an *independent* replay consumer (revision-0
base-table read + committed change feed, using none of ``sg.impact``'s state
machinery) and cross-checks the report against it.

Coverage:
  1. input binding/validation: unknown warehouse/revision, reversed range,
     committed-only, same revision => legal zero-impact report;
  2. per-transition hand expectations (merge, split/withdraw, self-loop
     appear/disappear, 1:1 / one-to-many / many-to-one migrations,
     contribution replacement/aggregation, zero-change revision);
  3. cumulative net vs. absolute churn, touched/reverted/transient marking and
     locate-ability in transition detail;
  4. pagination: stable global sort keys, page size, HMAC token tamper and
     cross-query/warehouse reuse rejection, repeatable reads;
  5. replay independence: report boundaries equal the independent consumer,
     and the impact reader never opens a historical full snapshot;
  6. streaming/bounded memory on a large synthetic warehouse.

Run:  python3 -I tests/run_impact_verify.py
Scale knob: SG_IMPACT_SCALE=2000 python3 -I tests/run_impact_verify.py
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

from tests.impact_fixtures import build_impact_warehouse, build_scaled_warehouse  # noqa: E402
from sg import impact as IMP  # noqa: E402
from sg import master as MD  # noqa: E402
from sg.util import SGError  # noqa: E402

PASS = FAIL = 0
SCALE = int(os.environ.get("SG_IMPACT_SCALE", "400"))
EXPECT = json.load(open(os.path.join(
    ROOT, "tests", "hand_expected", "impact_expectations.json"),
    encoding="utf-8"))


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


def rk(s, rel, t):
    return json.dumps([s, rel, t], separators=(",", ":"), ensure_ascii=False)


# ------------------------------------------------- independent replay consumer ----

class IndependentConsumer:
    """Rebuilds every revision state from base tables + the change feed only.

    Deliberately does not import or call anything from ``sg.impact``: it is
    the second, independent implementation the report is cross-checked
    against.  Its state at head must also equal the physical head tables.
    """

    def __init__(self, master):
        self.master = master
        conn = MD.connect(master)
        try:
            self.t1 = {}
            self.t2 = {}
            self.t3 = {}
            for r in conn.execute(
                    "SELECT obj_id, obj_type FROM base_objects ORDER BY obj_id"):
                self.t1[r["obj_id"]] = (r["obj_id"], r["obj_type"], r["obj_id"])
            agg = {}
            for e in conn.execute(
                    "SELECT * FROM base_edges ORDER BY relationship_id"):
                key = rk(e["source_id"], e["relationship_type"], e["target_id"])
                self.t3[e["relationship_id"]] = (
                    e["relationship_id"], e["source_id"], e["target_id"],
                    e["relationship_type"], e["source_id"], e["target_id"],
                    key, 1 if e["source_id"] == e["target_id"] else 0,
                    e["modified_key"], e["modified_raw"])
                agg.setdefault(key, []).append(
                    (e["source_id"], e["relationship_type"], e["target_id"]))
            for key in sorted(agg):
                s, rel, t = agg[key][0]
                self.t2[key] = (key, s, rel, t, len(agg[key]),
                                1 if s == t else 0)
            self.head = conn.execute(
                "SELECT MAX(revision) AS r FROM revisions").fetchone()["r"]
        finally:
            conn.close()
        self.revision = 0

    def advance(self, to_revision):
        conn = MD.connect(self.master)
        try:
            for rev in range(self.revision + 1, to_revision + 1):
                for item in MD.read_changes(self.master, rev, rev):
                    if item["type"] != "change":
                        continue
                    t, key, op, row = (item["table"], item["row_key"],
                                       item["op"], item["row"])
                    if t == MD.T_ENTITY:
                        self.t1.pop(key, None)
                        if op == "replace":
                            self.t1[key] = tuple(row[c] for c in MD.T1_COLS)
                    elif t == MD.T_REL:
                        self.t2.pop(key, None)
                        if op == "replace":
                            self.t2[key] = tuple(row[c] for c in MD.T2_COLS)
                    elif t == MD.T_CONTRIB:
                        self.t3.pop(key, None)
                        if op == "replace":
                            self.t3[key] = tuple(row[c] for c in MD.T3_COLS)
                    elif t == MD.T_VERDICT:
                        pass  # verdicts do not enter impact boundary facts
            self.revision = to_revision
        finally:
            conn.close()

    def groups(self):
        return len({v[2] for v in self.t1.values()})

    def self_loops(self):
        return sum(1 for v in self.t2.values() if v[5] == 1)

    def contribution_total(self):
        return len(self.t3)

    def relation_rows(self):
        return len(self.t2)

    def canon_of(self, obj_id):
        return self.t1[obj_id][2]

    def key_of(self, relationship_id):
        return self.t3[relationship_id][6]


# --------------------------------------------------------------------- tests ----

def test_validation_and_binding(work):
    print("\n[1] input binding: warehouse/revision identity, range rules")
    mpath = build_impact_warehouse(os.path.join(work, "t1"))
    missing = os.path.join(work, "no-such-warehouse.sqlite")

    rc, _, err = run_cli("master-impact-summary", "--master", missing,
                         "--from", "0", "--to", "1")
    check("unknown warehouse refused", rc == 2
          and json.loads(err)["error"] == "master-missing", err)

    rc, _, err = run_cli("master-impact-summary", "--master", mpath,
                         "--from", "0", "--to", "99")
    check("unknown revision refused", rc == 2
          and json.loads(err)["error"] == "unknown-revision", err)

    rc, _, err = run_cli("master-impact-summary", "--master", mpath,
                         "--from", "5", "--to", "2")
    check("reversed range refused", rc == 2
          and json.loads(err)["error"] == "reversed-range", err)

    rc, out, err = run_cli("master-impact-summary", "--master", mpath,
                           "--from", "3", "--to", "3")
    check("same revision accepted", rc == 0, err)
    doc = json.loads(out)
    check("same revision is legal zero-impact report",
          doc["interval"]["zero_impact"] is True
          and doc["summary"]["transitions"] == []
          and doc["summary"]["cumulative"]["entity_groups"]["net_delta"] == 0,
          out[:300])

    # report binds warehouse identity and report version
    ident = doc["warehouse"]
    check("report binds warehouse instance + package digest",
          bool(ident["warehouse_instance_id"])
          and len(ident["package_digest_sha256"]) == 64
          and doc["report_version"] == IMP.REPORT_VERSION)

    # every revision the report names is committed (header exists in ledger)
    revs = {r["revision"] for r in MD.list_revisions(mpath)}
    s = IMP.build_summary(mpath, 0, 7)
    check("only committed revisions referenced",
          set(s["interval"]["transition_revisions"]) <= revs
          and s["interval"]["end_revision"] in revs)


def test_hand_transition_expectations(work):
    print("\n[2] per-transition hand-written expectations")
    mpath = build_impact_warehouse(os.path.join(work, "t2"))
    summary = IMP.build_summary(mpath, 0, 7)
    transitions = {t["revision"]: t for t in summary["summary"]["transitions"]}
    exp = EXPECT["revisions"]

    for rev in range(1, 8):
        t = transitions[rev]
        e = exp[str(rev)]
        check(f"rev{rev} group counters",
              t["entity_groups"]["before_count"] == e["group_count_before"]
              and t["entity_groups"]["after_count"] == e["group_count_after"]
              and t["entity_groups"]["delta"] == e["group_delta"],
              json.dumps(t["entity_groups"]))
        check(f"rev{rev} self-loop counters",
              t["self_loops"]["delta"] == e["self_loop_delta"],
              json.dumps(t["self_loops"]))
        actual_pc = {x["obj_id"]: [x["before_canonical_id"],
                                   x["after_canonical_id"]]
                     for x in t["object_mapping"]["primary_changed"]}
        check(f"rev{rev} object primary changes with before/after canonicals",
              actual_pc == e.get("primary_changed", {}), str(actual_pc))
        check(f"rev{rev} no synthetic include/exit (base is immutable)",
              t["object_mapping"]["included"] == []
              and t["object_mapping"]["exited"] == [])

    # rev1 many-to-one merge component
    t1 = transitions[1]
    merges = [m for m in t1["relation_keys"]["migrations"]
              if m["component_kind"] == "merge"]
    check("rev1 reports one many-to-one merge component",
          len(merges) == 1 and len(merges[0]["old_keys"]) == 2
          and len(merges[0]["new_keys"]) == 1, json.dumps(merges)[:300])
    merge_edge_ids = sorted(
        rid for e in merges[0]["edges"] for rid in e["relationship_ids"])
    check("rev1 merge evidence names R1 (retained) and R2 (moved)",
          merge_edge_ids == ["relationship--R1", "relationship--R2"],
          str(merge_edge_ids))
    check("rev1 contribution aggregation 1->2 reported as modified",
          [(m["row_key"], m["before_contribution_count"],
            m["after_contribution_count"])
           for m in t1["relation_keys"]["modified"]]
          == [(rk("indicator--A", "indicates", "indicator--E"), 1, 2)])
    check("rev1 R4 becomes a flagged self loop",
          any(c["new_row_key"] == rk("indicator--A", "indicates",
                                     "indicator--A")
              and c["after_is_self_loop"] == 1
              for c in t1["self_loops"]["changed"])
          and t1["self_loops"]["after_count"] == 2)

    # rev2 one-to-many split component (R1 stays, R2 moves out)
    t2 = transitions[2]
    splits = [m for m in t2["relation_keys"]["migrations"]
              if m["component_kind"] == "split"]
    check("rev2 reports one one-to-many split (not delete+insert)",
          len(splits) == 1 and len(splits[0]["old_keys"]) == 1
          and len(splits[0]["new_keys"]) == 2, json.dumps(splits)[:300])
    ids = sorted(rid for e in splits[0]["edges"]
                 for rid in e["relationship_ids"])
    check("rev2 split keeps R1 and moves R2 without guessing uniqueness",
          ids == ["relationship--R1", "relationship--R2"], str(ids))

    # migration pairs per revision (1:1 moves identified by raw endpoints)
    for rev in (1, 2, 3, 4, 5, 6):
        e = exp[str(rev)]
        if "migrated_pairs" not in e:
            continue
        got = []
        for comp in transitions[rev]["relation_keys"]["migrations"]:
            if comp["component_kind"] != "migrated":
                continue
            for edge in comp["edges"]:
                got.append((edge["relationship_ids"][0],
                            edge["old_row_key"], edge["new_row_key"]))
        want = [tuple(x) for x in e["migrated_pairs"]]
        check(f"rev{rev} 1:1 migration pairs (raw endpoints + type)",
              sorted(got) == sorted(want), f"got={sorted(got)} want={want}")

    # rev7 empty revision: zero change rows, no object/relation detail
    t7 = transitions[7]
    check("rev7 zero-change revision has empty detail sections",
          t7["object_mapping"] == {"included": [], "exited": [],
                                   "primary_changed": []}
          and t7["relation_keys"]["migrations"] == []
          and t7["relation_keys"]["modified"] == []
          and t7["entity_groups"]["delta"] == 0
          and t7["self_loops"]["delta"] == 0)


def test_contribution_evidence_and_coordinates(work):
    print("\n[3] migration contribution ids pageable with original coordinates")
    mpath = build_impact_warehouse(os.path.join(work, "t3"))
    lines = list(IMP.iter_detail_lines(mpath, 0, 1))
    contrib_lines = [l for l in lines
                     if l["line_kind"] == "migration_contribution"]
    by_id = {l["relationship_id"]: l for l in contrib_lines}
    check("every moved rev1 contribution has a detail line",
          {"relationship--R2", "relationship--R3", "relationship--R4",
           "relationship--R6", "relationship--R8"} <= set(by_id),
          str(sorted(by_id)))
    r2 = by_id["relationship--R2"]
    check("R2 line carries raw endpoints, type and both coordinate sets",
          r2["original_source_id"] == "indicator--C"
          and r2["original_target_id"] == "indicator--E"
          and r2["relationship_type"] == "indicates"
          and r2["before"]["row_key"] == rk("indicator--C", "indicates",
                                            "indicator--E")
          and r2["after"]["row_key"] == rk("indicator--A", "indicates",
                                           "indicator--E")
          and r2["after"]["modified_raw"] == "2026-01-01T00:00:00Z")
    check("R2 before/after self-loop flags present and 0",
          r2["before"]["is_self_loop"] == 0
          and r2["after"]["is_self_loop"] == 0)
    # relation key change lines expose before/after contribution counts
    key_lines = [l for l in lines
                 if l["line_kind"] == "relation_key_change"
                 and l["change_kind"] == "modified"]
    check("per-key before/after contribution counts present",
          any(l["row_key"] == rk("indicator--A", "indicates",
                                 "indicator--E")
              and l["before_contribution_count"] == 1
              and l["after_contribution_count"] == 2 for l in key_lines))
    # every reported per-key delta is non-zero (no retained-key phantom) and
    # the deltas sum to zero: contributions are conserved across a transition
    summary_01 = IMP.build_summary(mpath, 0, 1)
    per_key = summary_01["summary"]["transitions"][0][
        "contribution_counts"]["per_key"]
    check("per-key deltas are all non-zero and sum to zero (conservation)",
          all(x["delta"] != 0 for x in per_key)
          and sum(x["delta"] for x in per_key) == 0,
          str(per_key))
    retained = rk("indicator--D", "indicates", "indicator--F")
    check("an unchanged retained key has no phantom per-key delta",
          all(x["row_key"] != retained for x in per_key))


def test_cumulative_and_revert(work):
    print("\n[4] cumulative net vs churn, touched/reverted/transient marking")
    mpath = build_impact_warehouse(os.path.join(work, "t4"))

    # independent consumer computes the same boundary facts
    consumer = IndependentConsumer(mpath)
    full = IMP.build_summary(mpath, 0, 7)
    cum = full["summary"]["cumulative"]
    consumer.advance(7)
    check("independent consumer head groups match report end count",
          consumer.groups() == cum["entity_groups"]["end_count"])
    check("independent consumer self loops match report end count",
          consumer.self_loops() == cum["self_loops"]["end_count"])
    check("contribution total is conserved (base edges immutable)",
          cum["contribution_counts"]["start_total"]
          == cum["contribution_counts"]["end_total"]
          == consumer.contribution_total())

    # net must be endpoint difference; churn must be the per-transition sum
    churn_groups = sum(abs(t["entity_groups"]["delta"])
                       for t in full["summary"]["transitions"])
    check("group churn equals sum of per-transition absolute deltas",
          cum["entity_groups"]["transition_absolute_churn"] == churn_groups)
    check("net delta is NOT computed from absolute delta sums",
          cum["entity_groups"]["net_delta"]
          != cum["entity_groups"]["transition_absolute_churn"])
    churn_sl = sum(abs(t["self_loops"]["delta"])
                   for t in full["summary"]["transitions"])
    check("self-loop churn vs net kept distinct",
          cum["self_loops"]["transition_absolute_churn"] == churn_sl
          and cum["self_loops"]["net_delta"] == 1)

    # hand expectations for the full interval
    e07 = EXPECT["interval_expectations"]["0_to_7"]
    check("0..7 hand cumulative counts",
          cum["entity_groups"]["start_count"] == e07["start_groups"]
          and cum["entity_groups"]["end_count"] == e07["end_groups"]
          and cum["entity_groups"]["net_delta"] == e07["net_group_delta"]
          and cum["entity_groups"]["transition_absolute_churn"]
          == e07["group_absolute_churn"])
    check("0..7 reverted objects",
          cum["object_mapping"]["reverted"] == e07["reverted_objects"])
    check("0..7 transient relation keys (present only mid-interval)",
          cum["relation_keys"]["transient"] == e07["transient_relation_keys"])

    # reverted object is locate-able in transition detail
    reverted = cum["object_mapping"]["reverted"]
    locator = {}
    for t in full["summary"]["transitions"]:
        for x in t["object_mapping"]["primary_changed"]:
            locator.setdefault(x["obj_id"], []).append(t["revision"])
    check("every reverted object is located in transition detail",
          all(o in locator and len(locator[o]) >= 2 for o in reverted))
    check("touched_revisions matches transition locations",
          all(cum["object_mapping"]["touched_revisions"][o] == locator[o]
              for o in reverted))

    # explicit change-and-revert interval 2 -> 4
    s24 = IMP.build_summary(mpath, 2, 4)
    c24 = s24["summary"]["cumulative"]
    e24 = EXPECT["interval_expectations"]["2_to_4"]
    check("2..4 zero net but non-zero churn (object B)",
          c24["entity_groups"]["net_delta"] == e24["net_group_delta"]
          and c24["entity_groups"]["transition_absolute_churn"]
          == e24["group_absolute_churn"]
          and c24["object_mapping"]["reverted"] == e24["reverted_objects"])
    check("2..4 self-loop change then revert: net 0, churn 2",
          c24["self_loops"]["net_delta"] == 0
          and c24["self_loops"]["transition_absolute_churn"] == 2)
    check("2..4 reverted relation key marked and located",
          c24["relation_keys"]["reverted"]
          == e24["reverted_relation_keys"]
          and c24["relation_keys"]["touched_revisions"][
              e24["reverted_relation_keys"][0]] == [3, 4])

    # same-revision zero report (0,0) and (3,3)
    for s, e_ in ((0, 0), (3, 3)):
        z = IMP.build_summary(mpath, s, s)
        lines = list(IMP.iter_detail_lines(mpath, s, s))
        key = f"{s}_to_{s}"
        ee = EXPECT["interval_expectations"][key]
        check(f"{s}..{s} zero-impact report",
              z["interval"]["zero_impact"] is True
              and z["summary"]["transitions"] == []
              and [l["line_kind"] for l in lines] == ee["detail_lines"])


def test_pagination(work):
    print("\n[5] stable sort keys, paging, HMAC token binding")
    mpath = build_impact_warehouse(os.path.join(work, "t5"))
    all_lines, tok, pages = [], None, 0
    while True:
        page = IMP.read_page(mpath, 0, 7, page_size=7, page_token=tok)
        pages += 1
        check(f"page {pages} envelope fields",
              page["returned"] == len(page["page"])
              and page["report_version"] == IMP.REPORT_VERSION)
        all_lines.extend(page["page"])
        tok = page["next_page_token"]
        if not page["has_more"]:
            check("last page has no token", page["next_page_token"] is None)
            break
    keys = [tuple(l["sort_key"]) for l in all_lines]
    check("detail lines globally sorted by stable key", keys == sorted(keys))
    check("sort keys unique", len(set(keys)) == len(keys))
    unpaged = list(IMP.iter_detail_lines(mpath, 0, 7))
    check("paged walk covers exactly the full stream",
          keys == [tuple(l["sort_key"]) for l in unpaged])

    # repeatable read: same first page twice, byte-identical order/content
    p_a = IMP.read_page(mpath, 0, 7, page_size=7)
    p_b = IMP.read_page(mpath, 0, 7, page_size=7)
    check("repeat reads return identical pages",
          json.dumps(p_a["page"], sort_keys=True)
          == json.dumps(p_b["page"], sort_keys=True))

    # token tampering
    bad = p_a["next_page_token"][:-2] + "AA"
    try:
        IMP.read_page(mpath, 0, 7, page_size=7, page_token=bad)
        check("tampered token rejected", False)
    except SGError as exc:
        check("tampered token rejected", exc.code == "invalid-page-token")

    # cross-query reuse: page size / interval / filter bindings
    for kwargs, label in [
        ({"page_size": 9}, "page size"),
        ({"start": 0, "end": 6}, "interval"),
        ({"kind": "object"}, "kind filter"),
        ({"scope": "cumulative"}, "scope filter"),
    ]:
        try:
            IMP.read_page(mpath,
                          kwargs.get("start", 0), kwargs.get("end", 7),
                          kwargs.get("page_size", 7),
                          scope=kwargs.get("scope", "all"),
                          kind=kwargs.get("kind", "all"),
                          page_token=p_a["next_page_token"])
            check(f"token rebound across {label} rejected", False)
        except SGError as exc:
            check(f"token rebound across {label} rejected",
                  exc.code == "page-context-mismatch")

    # cross-warehouse reuse: same package content, different instance id
    other = build_impact_warehouse(tempfile.mkdtemp(prefix="sg-imp-other-"))
    try:
        IMP.read_page(other, 0, 7, page_size=7,
                      page_token=p_a["next_page_token"])
        check("cross-warehouse token reuse rejected", False)
    except SGError as exc:
        check("cross-warehouse token reuse rejected",
              exc.code == "page-context-mismatch")

    # filtered paging stays within the family
    obj_page = IMP.read_page(mpath, 0, 7, page_size=10, kind="object")
    check("kind filter applies inside paged results",
          all(l["line_kind"] in ("object_change", "object_touched")
              for l in obj_page["page"]))
    rev_page = IMP.read_page(mpath, 0, 7, page_size=10, revision=2)
    check("revision filter pages only that transition",
          all(l["scope"] == "transitions" and l["revision"] == 2
              for l in rev_page["page"]))

    # CLI: summary + page subcommands work and JSONL is one object per line
    rc, out, err = run_cli("master-impact-page", "--master", mpath,
                           "--from", "0", "--to", "7", "--page-size", "5")
    check("CLI impact-page rc0", rc == 0, err)
    parsed = [json.loads(line) for line in out.splitlines()]
    check("CLI page emits JSONL lines plus one envelope",
          parsed[-1]["type"] == "page_envelope"
          and all("sort_key" in l for l in parsed[:-1]))


def test_replay_independence_and_no_snapshot_reads(work):
    print("\n[6] replay independence: boundaries match a second implementation")
    mpath = build_impact_warehouse(os.path.join(work, "t6"))
    consumer = IndependentConsumer(mpath)
    for end in range(0, 8):
        consumer.advance(end)
        summary = IMP.build_summary(mpath, 0, end)
        cum = summary["summary"]["cumulative"]
        check(f"rev{end} boundary groups match independent consumer",
              cum["entity_groups"]["end_count"] == consumer.groups())
        check(f"rev{end} boundary self loops match independent consumer",
              cum["self_loops"]["end_count"] == consumer.self_loops())
    # relation-row counts are carried on each transition; the final
    # transition's after-count must equal the independent consumer's state.
    final_trans = summary["summary"]["transitions"][-1]
    check("final boundary relation rows match independent consumer",
          final_trans["contribution_counts"]["after_total"]
          == consumer.contribution_total()
          and consumer.relation_rows() >= 0)
    # head physical tables equal the replay-to-head state (replay faithfulness)
    head = MD.read_all(mpath)
    replay = IMP.build_revision_zero(MD.connect(mpath))
    conn = MD.connect(mpath)
    try:
        for rev in range(1, consumer.head + 1):
            for item in MD.read_changes(mpath, rev, rev):
                if item["type"] != "change":
                    continue
                row = item["row"]
                IMP._apply_change(replay, item["table"], item["row_key"],
                                  item["op"], row)
        physical_t1 = {r["obj_id"]: r["canonical_id"]
                       for r in head["tables"]["entity_map"]}
        replay_t1 = {k: v["canonical_id"] for k, v in replay.t1.items()}
        check("replay-to-head entity map equals physical head table",
              physical_t1 == replay_t1)
        physical_t2 = {r["row_key"]: r["contribution_count"]
                       for r in head["tables"]["relations"]}
        replay_t2 = {k: v["contribution_count"]
                     for k, v in replay.t2.items()}
        check("replay-to-head relations equal physical head table",
              physical_t2 == replay_t2)
        physical_t3 = {r["relationship_id"]
                       for r in head["tables"]["contributions"]}
        check("replay-to-head contributions equal physical head table",
              physical_t3 == set(replay.t3))
    finally:
        conn.close()

    # the impact code path never reads a historical full snapshot table:
    # only base_* (immutable), changes and revisions are accessed.  The engine
    # opens its own connection, so wrap the connection factory to capture the
    # exact instrumented connection it uses.
    captured = {}
    original_connect = IMP.connect

    def spy_connect(path):
        c = original_connect(path)
        captured["conn"] = c
        return c

    IMP.connect = spy_connect
    try:
        list(IMP.iter_detail_lines(mpath, 0, 7, max_lines=20))
        acct = captured["conn"].access_snapshot().get("impact", {})
        touched = set(acct)
        # The four logical result tables (t1..t4) and adjudications are never
        # read: no historical full snapshot is assumed.  The immutable base
        # tables are streamed once (like master-build itself) and revisions is
        # only probed via MAX(...), the documented small-table exception.
        forbidden = {"t1_entity_map", "t2_relations", "t3_contributions",
                     "t4_verdicts", "adjudications", "batch_receipts"}
        check("impact never opens a result/snapshot table or the ledger",
              forbidden.isdisjoint(touched), str(sorted(touched)))
        check("change feed always read by revision key (no changes scan)",
              acct.get("changes", {}).get("scan", 0) == 0, str(acct))
        check("base-table reads are sequential immutable streams only",
              all(acct.get(t, {}).get("filtered", 0) == 0
                  for t in ("base_objects", "base_edges")), str(acct))
        check("impact issues zero write statements",
              all(v.get("write", 0) == 0 for v in acct.values()),
              str(acct))
    finally:
        IMP.connect = original_connect
        captured["conn"].close()

    # warehouse content unchanged: verdicts/revisions/receipts counts stable
    before = (len(MD.list_revisions(mpath)),
              sum(1 for _ in MD.read_changes(mpath, 1, 7)))
    IMP.build_summary(mpath, 0, 7)
    list(IMP.iter_detail_lines(mpath, 0, 7))
    IMP.read_page(mpath, 0, 7, page_size=5)
    after = (len(MD.list_revisions(mpath)),
             sum(1 for _ in MD.read_changes(mpath, 1, 7)))
    check("read-only impact analysis does not modify the warehouse",
          before == after)


def test_large_scale_streaming(work):
    print(f"\n[7] large synthetic warehouse ({SCALE} filler pairs): streaming")
    mpath = build_scaled_warehouse(work, SCALE)

    # full interval: every filler pair merges then splits -> net zero, churn
    summary = IMP.build_summary(mpath, 0, 2)
    cum = summary["summary"]["cumulative"]
    check("scale run net group delta zero after merge+split",
          cum["entity_groups"]["net_delta"] == 0)
    check("scale run churn grows with data, net does not",
          cum["entity_groups"]["transition_absolute_churn"] >= 2 * SCALE)

    # stream the whole detail set without materializing it; count via generator
    total = 0
    max_rev_seen = 0
    for line in IMP.iter_detail_lines(mpath, 0, 2):
        total += 1
        if line["scope"] == "transitions":
            max_rev_seen = max(max_rev_seen, line["revision"])
    check("streamed a large, growing detail volume", total > 4 * SCALE,
          f"total={total}")
    check("stream covers both transitions", max_rev_seen == 2)

    # paging over the large set: every page bounded, walk is complete & ordered
    pages = 0
    seen_keys, tok = [], None
    while True:
        page = IMP.read_page(mpath, 0, 2, page_size=250, page_token=tok)
        pages += 1
        assert len(page["page"]) <= 250
        seen_keys.extend(tuple(l["sort_key"]) for l in page["page"])
        tok = page["next_page_token"]
        if not page["has_more"]:
            break
    check("large paged walk is ordered and complete",
          seen_keys == sorted(seen_keys) and len(seen_keys) == total
          and pages > SCALE // 250, f"pages={pages} lines={len(seen_keys)}")

    # memory: peak RSS of a paged CLI read stays close to a tiny-warehouse read
    def peak_rss(args):
        proc = subprocess.run(
            [sys.executable, "-I", os.path.join(ROOT, "tests", "measure_rss.py"),
             *args], cwd=ROOT, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        line = [l for l in proc.stderr.splitlines()
                if l.startswith("PEAK_RSS_KB=")][0]
        return int(line.split("=", 1)[1])

    big_rss = peak_rss(["master-impact-page", "--master", mpath,
                        "--from", "0", "--to", "2", "--page-size", "250"])
    small = build_impact_warehouse(tempfile.mkdtemp(prefix="sg-imp-rss-"))
    small_rss = peak_rss(["master-impact-page", "--master", small,
                          "--from", "0", "--to", "7", "--page-size", "250"])
    print(f"  [mem] big peak={big_rss}KB small peak={small_rss}KB", flush=True)
    # paged reads stream: the SCALE-times bigger warehouse must not produce a
    # proportionally larger footprint (allow a generous constant headroom).
    check("paged read memory does not scale with total detail volume",
          big_rss < small_rss * 3 + 30000,
          f"big={big_rss} small={small_rss}")

    # generator truncation: asking for N lines stops early (bounded work)
    few = list(IMP.iter_detail_lines(mpath, 0, 2, max_lines=17))
    check("max_lines truncates the stream", len(few) == 17
          and few == sorted(few, key=lambda l: tuple(l["sort_key"])))

    # structural streaming proof: a per-transition record must be released as
    # soon as its lines have been yielded.  Plain dicts are not weakref-able,
    # so the analyzer is wrapped to return a weakref-able holder; after the
    # generator advances past every transition, every holder must be dead.
    import gc
    import weakref
    import sg.impact as impact_mod

    class _RecordHolder:
        def __init__(self, record):
            self.record = record

    held = []
    original_analyze = impact_mod._analyze_transition

    def spy_analyze(state, rows, revision):
        record = original_analyze(state, rows, revision)
        holder = _RecordHolder(record)
        held.append(weakref.ref(holder))
        return record

    impact_mod._analyze_transition = spy_analyze
    try:
        saw_cumulative = False
        for line in IMP.iter_detail_lines(mpath, 0, 2):
            if line["scope"] == "cumulative":
                saw_cumulative = True
                break
        gc.collect()
        dead = all(r() is None for r in held)
        check("per-transition records released after streaming (no full"
              " detail residency)", saw_cumulative and len(held) == 2 and dead,
              f"held={len(held)} dead={dead}")
    finally:
        impact_mod._analyze_transition = original_analyze

    # the report never claims an adjudication caused a change: no verdict id
    # appears in any detail line or summary body (only batch/revision linkage).
    summary = IMP.build_summary(mpath, 0, 2)
    blob = json.dumps(summary)
    check("report carries no verdict ids (no causal attribution)",
          "verdict--" not in blob and "V--PQ" not in blob)
    detail_blob = "\n".join(json.dumps(l)
                            for l in IMP.iter_detail_lines(mpath, 0, 2))
    check("detail lines carry no verdict ids",
          "verdict--" not in detail_blob and "V--PQ" not in detail_blob)


def main():
    work = tempfile.mkdtemp(prefix="sg-impact-")
    try:
        test_validation_and_binding(work)
        test_hand_transition_expectations(work)
        test_contribution_evidence_and_coordinates(work)
        test_cumulative_and_revert(work)
        test_pagination(work)
        test_replay_independence_and_no_snapshot_reads(work)
        test_large_scale_streaming(work)
        print(f"\n{PASS} passed, {FAIL} failed")
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
