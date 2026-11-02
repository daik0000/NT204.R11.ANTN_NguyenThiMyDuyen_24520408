import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.content_matcher import content_fn, match_contents
from src.engine.matcher import match_rule
from src.engine.stats import EvaluationStats
from src.pipeline.pipeline import _parse_packet_layers
from src.rules.indexer import RuleIndexer
from src.rules.repository import RuleRepository

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_other_mismatches"       # evidence of the second run (variants.pcap)
ROOT = CASE_DIR.parents[2]
SID = 7001

# --- worked out by hand BEFORE running anything -----------------------------------------------------------------
# The rule: alert tcp 10.0.0.5 any -> 192.168.1.20 80 (content:"GET"; sid:7001). Every packet carries "GET / HTTP/1.1",
# so the content would match all of them: only the header (or the index) can keep a packet from firing.
#
# input.pcap
#   (a) 10.0.0.5:52133 -> 192.168.1.20:80    candidate (tcp, dst 80)  header ok            -> content searched -> DETECTION
#   (b) 10.0.0.5:52134 -> 10.9.9.9:80        candidate (tcp, dst 80)  header FAILS (dst IP) -> content never searched
#   (c) 10.0.0.5:52135 -> 192.168.1.20:8080  NOT a candidate (the rule is filed under port 80)
#   candidate_rules = 2 (a, b)   rejected_header = 1 (b)   content_evaluations = 1 (a only)   matches = 1
#
# variants.pcap (the content matches these too)
#   (d) 10.9.9.9 -> 192.168.1.20:80      candidate, header FAILS (source IP)
#   (e) UDP 10.0.0.5 -> 192.168.1.20:80  not a candidate (the rule is tcp)
#   (f) 192.168.1.20:80 -> 10.0.0.5:52138 not a candidate (destination port 52138; the rule is one-way)
#   (g) 10.0.0.5 -> 192.168.1.21:80      candidate, header FAILS (destination IP .21)
#   candidate_rules = 2 (d, g)   rejected_header = 2   content_evaluations = 0   matches = 0
EXPECTED_MAIN = {"candidates": 2, "rejected_header": 1, "content_evaluations": 1, "matches": 1, "detection_packets": [1]}
EXPECTED_VARIANT = {"candidates": 2, "rejected_header": 2, "content_evaluations": 0, "matches": 0, "detection_packets": []}
CANDIDATE_PACKETS_MAIN = {1: True, 2: True, 3: False}
CANDIDATE_PACKETS_VARIANT = {1: True, 2: False, 3: False, 4: True}


def load_rule():
    _, _, rules = run_rules_only(CASE_DIR / "rules.rules")
    return rules[0]


def events_of(pcap):
    return [_parse_packet_layers(ts, raw, i) for i, (ts, raw) in enumerate(read_pcap(str(pcap)), start=1)]


def engine_line(stderr):
    return [l for l in stderr.splitlines() if "| engine:" in l][-1]


@pytest.fixture(scope="module")
def run():
    stderr = []
    return run_case_ids(CASE_DIR, rules=["rules.rules"], stderr_out=stderr) + (stderr[0],)


@pytest.fixture(scope="module")
def variant():
    VARIANT_DIR.mkdir(exist_ok=True)
    stderr = []
    out = run_case_ids(VARIANT_DIR, rules=[CASE_DIR / "rules.rules"], pcap_name="../variants.pcap", stderr_out=stderr)
    return out + (stderr[0],)


# --- the counters of the issue ------------------------------------------------------------------------------------------------

def test_only_packet_a_produces_a_detection(run):
    detections = run[2]
    assert [(d["packet_id"], d["sid"]) for d in detections] == [(1, SID)]
    d = detections[0]
    assert (d["src_ip"], d["dst_ip"], d["dst_port"]) == ("10.0.0.5", "192.168.1.20", 80)
    assert d["matched"] == [{"keyword": "content", "value": "GET", "offset": 0, "length": 3}]


def test_statistics_prove_the_rejected_packets_never_reached_the_content_search(run):
    line = engine_line(run[4])
    assert "events_evaluated=3 " in line and f"candidate_rules={EXPECTED_MAIN['candidates']} " in line
    assert f"rejected_header={EXPECTED_MAIN['rejected_header']} " in line and "rejected_flow=0 " in line and "rejected_packet=0 " in line
    assert f"content_evaluations={EXPECTED_MAIN['content_evaluations']} " in line and "rejected_content=0 " in line
    assert f"matches={EXPECTED_MAIN['matches']} " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "events_evaluated=3, candidates=2, detections=1" in summary


def test_the_rule_is_valid_and_all_three_packets_are_processed(run):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", SID)]
    assert len(run[0]) == 3 and all(e["status"] == "OK" for e in run[0])


# --- packet by packet, with the real MatchResult ------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stage_results():
    rule = load_rule()
    spy_calls = []

    def spy(r, e):
        spy_calls.append(e.packet_id)
        return content_fn(r, e)

    results = {}
    for event in events_of(CASE_DIR / "input.pcap"):
        stats = EvaluationStats()
        results[event.packet_id] = (match_rule(rule, event, None, spy, stats), stats)
    return results, spy_calls


def test_packet_a_matched_packet_b_failed_at_the_header(stage_results):
    results, _ = stage_results
    a, b = results[1][0], results[2][0]
    assert (a.matched, a.failed_stage) == (True, None)
    assert (b.matched, b.failed_stage) == (False, "header")
    assert b.matches == []


def test_the_content_search_ran_for_packet_a_only(stage_results):
    results, spy_calls = stage_results
    assert spy_calls == [1]                                              # content_fn was never called for packets 2 and 3
    assert results[1][1].content_evaluations == 1
    assert results[2][1].content_evaluations == 0 and results[2][1].rules_rejected_header == 1


def test_packet_c_would_also_fail_the_header_if_it_were_tried(stage_results):
    results, _ = stage_results
    assert results[3][0].failed_stage == "header"                        # destination port 8080 is not 80


def test_the_index_never_offers_the_rule_for_packet_c():
    rule = load_rule()
    repo = RuleRepository()
    repo.add(rule)
    repo.freeze()
    index = RuleIndexer(repo)
    events = {e.packet_id: e for e in events_of(CASE_DIR / "input.pcap")}
    offered = {pid: [r.sid for r in index.candidates(e.transport_protocol, e.dst_port)] == [SID] for pid, e in events.items()}
    assert offered == CANDIDATE_PACKETS_MAIN


def test_the_content_matches_all_three_packets_so_only_the_header_explains_the_rejection():
    rule = load_rule()
    for event in events_of(CASE_DIR / "input.pcap"):
        assert match_contents(rule, event.payload) == [{"keyword": "content", "value": "GET", "offset": 0, "length": 3}]


# --- variants: more ways to miss the header ------------------------------------------------------------------------------------------------

def test_variant_nothing_fires(variant):
    assert variant[2] == [] and len(variant[0]) == 4


def test_variant_statistics(variant):
    line = engine_line(variant[4])
    assert "events_evaluated=4 " in line and f"candidate_rules={EXPECTED_VARIANT['candidates']} " in line
    assert f"rejected_header={EXPECTED_VARIANT['rejected_header']} " in line
    assert "content_evaluations=0 " in line and "matches=0 " in line and "rule_errors=0" in line
    summary = [l for l in variant[4].splitlines() if "System shutdown complete" in l][-1]
    assert "events_evaluated=4, candidates=2, detections=0" in summary


def test_variant_each_packet_misses_the_header_and_the_content_is_never_searched():
    rule = load_rule()
    calls = []
    index_repo = RuleRepository()
    index_repo.add(rule)
    index_repo.freeze()
    index = RuleIndexer(index_repo)
    for event in events_of(CASE_DIR / "variants.pcap"):
        result = match_rule(rule, event, None, lambda r, e: calls.append(e.packet_id))
        assert (result.matched, result.failed_stage) == (False, "header"), event.packet_id
        offered = [r.sid for r in index.candidates(event.transport_protocol, event.dst_port)] == [SID]
        assert offered is CANDIDATE_PACKETS_VARIANT[event.packet_id]
        assert match_contents(rule, event.payload) is not None             # the content itself would have matched
    assert calls == []


# --- evidence and reproducibility ---------------------------------------------------------------------------------------------------------

def test_evidence_files_exist_in_both_directories(run, variant):
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_the_pcaps_are_reproducible():
    spec = importlib.util.spec_from_file_location("t07_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    for name, packets in (("input.pcap", module.PACKETS), ("variants.pcap", module.VARIANT_PACKETS)):
        rebuilt = Path(write_pcap(packets, str(CASE_DIR / "_rebuilt.pcap")))
        try:
            assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / name).read_bytes()).hexdigest()
        finally:
            rebuilt.unlink(missing_ok=True)
