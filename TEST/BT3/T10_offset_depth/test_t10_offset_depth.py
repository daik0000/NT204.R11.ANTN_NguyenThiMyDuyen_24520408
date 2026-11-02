import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.content_matcher import absolute_window, find_absolute, match_contents
from src.pipeline.pipeline import _parse_packet_layers

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_edges"                  # evidence of the second run (variants.rules on the same pcap)
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything ------------------------------------------------------------------------------
# Payload ABCDEFGHIJ, 10 bytes:   A0 B1 C2 D3 E4 F5 G6 H7 I8 J9.   "CD" is at 2..4, "J" at 9..10.
# The search window of a content is [offset, offset + depth): depth is the SIZE of the window, not a position. A pattern has
# to lie completely inside it. Without depth the window runs to the end of the payload; without offset it starts at 0.
#
#   sid    content / modifiers          window     the pattern lies in it?            result
#   10001  "CD" offset 2 depth 2        [2, 4)     CD = 2..4, yes                      MATCH  offset 2
#   10002  "CD" offset 3                [3, 10)    CD begins at 2, before the window   NO
#   10003  "CD" depth 3                 [0, 3)     CD ends at 4, past the window       NO
#   10004  "CD" depth 4                 [0, 4)     CD = 2..4, yes                      MATCH  offset 2
#   10005  "J"  offset 9                [9, 10)    J = 9..10, yes                      MATCH  offset 9
#   10006  "J"  offset 10               [10, 10)   empty window                        NO
#   => 3 detections: 10001, 10004, 10005 with matched[0].offset 2, 2, 9
WINDOWS = {10001: (2, 4), 10002: (3, None), 10003: (0, 3), 10004: (0, 4), 10005: (9, None), 10006: (10, None)}
EXPECTED = {10001: 2, 10002: None, 10003: None, 10004: 2, 10005: 9, 10006: None}          # sid -> offset of the match
LENGTH = {10001: 2, 10004: 2, 10005: 1}
# Every rule has a content and nothing else: all 6 candidates enter the content stage -> content_evaluations 6,
# rejected_content 3, matches 3.
#
# variants.rules (same payload):
#   10101 "A"  depth 1           [0, 1)   yes  -> MATCH 0      10102 "IJ" offset 8 depth 2  [8, 10)  yes -> MATCH 8
#   10103 "IJ" offset 7 depth 2  [7, 9)   IJ ends at 10, no    10104 "CD" offset 0 depth 4  [0, 4)   yes -> MATCH 2
#   10105 "EF" offset 4 depth 2  [4, 6)   EF = 4..6, yes       10106 "EF" offset 5          [5, 10)  EF begins at 4, no
#   10107 "J"  offset 20         past the end: empty window, no (and no error)          10108 "A" offset 0   [0, 10)  yes -> MATCH 0
#   => 5 detections: 10101, 10102, 10104, 10105, 10108 (offsets 0, 8, 2, 4, 0); content_evaluations 8, rejected_content 3, matches 5
VARIANT_WINDOWS = {10101: (0, 1), 10102: (8, 10), 10103: (7, 9), 10104: (0, 4), 10105: (4, 6), 10106: (5, None),
                   10107: (20, None), 10108: (0, None)}
VARIANT_EXPECTED = {10101: 0, 10102: 8, 10103: None, 10104: 2, 10105: 4, 10106: None, 10107: None, 10108: 0}


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
    out = run_case_ids(VARIANT_DIR, rules=[CASE_DIR / "variants.rules"], pcap_name="../input.pcap", stderr_out=stderr)
    return out + (stderr[0],)


@pytest.fixture(scope="module")
def payload():
    (ts, raw), = list(read_pcap(str(CASE_DIR / "input.pcap")))
    return _parse_packet_layers(ts, raw, 1).payload


def specs(name):
    _, _, rules = run_rules_only(CASE_DIR / name)
    return {r.sid: r.contents[0] for r in rules}


# --- the windows of the hand calculation ----------------------------------------------------------------------------------------------

def test_the_payload_is_the_ten_bytes(payload):
    assert payload == b"ABCDEFGHIJ" and len(payload) == 10 and payload.index(b"CD") == 2 and payload.index(b"J") == 9


@pytest.mark.parametrize("sid", sorted(WINDOWS))
def test_search_window_of_each_rule(sid):
    assert absolute_window(specs("rules.rules")[sid]) == WINDOWS[sid]


def test_depth_is_the_size_of_the_window_not_a_position():
    s = specs("rules.rules")
    assert absolute_window(s[10001]) == (2, 4)            # offset 2 + depth 2; read as a position it would be the empty [2, 2)


@pytest.mark.parametrize("sid", sorted(EXPECTED))
def test_each_rule_on_the_payload_directly(payload, sid):
    position = find_absolute(payload, specs("rules.rules")[sid])
    assert (position if position >= 0 else None) == EXPECTED[sid]


# --- through main.py ------------------------------------------------------------------------------------------------------------------------

def test_three_detections_with_the_expected_offsets(run):
    assert [d["sid"] for d in run[2]] == [10001, 10004, 10005]
    assert [d["matched"][0]["offset"] for d in run[2]] == [2, 2, 9]
    assert [d["matched"] for d in run[2]] == [[{"keyword": "content", "value": v, "offset": o, "length": n}]
                                              for v, o, n in (("CD", 2, 2), ("CD", 2, 2), ("J", 9, 1))]


def test_the_other_three_rules_do_not_fire(run):
    assert {d["sid"] for d in run[2]}.isdisjoint({10002, 10003, 10006})


def test_the_packet_is_a_udp_datagram_to_a_port_without_a_parser(run):
    d = run[2][0]
    assert (d["protocol"], d["dst_port"], d["application_protocol"], d["packet_id"]) == ("UDP", 9999, "UNKNOWN", 1)


def test_counters(run):
    line = engine_line(run[4])
    assert "events_evaluated=1 " in line and "candidate_rules=6 " in line
    assert "rejected_header=0 " in line and "rejected_flow=0 " in line and "rejected_packet=0 " in line
    assert "content_evaluations=6 " in line and "rejected_content=3 " in line and "matches=3 " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=6, invalid=0, unsupported=0), events_evaluated=1, candidates=6, detections=3" in summary


def test_match_contents_gives_the_same_offsets(payload):
    _, _, rules = run_rules_only(CASE_DIR / "rules.rules")
    for rule in rules:
        found = match_contents(rule, payload)
        assert (found[0]["offset"] if found else None) == EXPECTED[rule.sid]


# --- variant: window edges, explicit offset 0, offset past the end ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", sorted(VARIANT_WINDOWS))
def test_variant_windows(sid):
    assert absolute_window(specs("variants.rules")[sid]) == VARIANT_WINDOWS[sid]


def test_variant_detections_and_offsets(variant):
    assert [(d["sid"], d["matched"][0]["offset"]) for d in variant[2]] == [
        (10101, 0), (10102, 8), (10104, 2), (10105, 4), (10108, 0)]
    fired = {d["sid"] for d in variant[2]}
    assert fired == {s for s, offset in VARIANT_EXPECTED.items() if offset is not None}


def test_variant_an_offset_past_the_end_is_just_no_match(variant):
    assert 10107 not in {d["sid"] for d in variant[2]}
    assert "rule_errors=0" in engine_line(variant[4])


def test_variant_counters(variant):
    line = engine_line(variant[4])
    assert "candidate_rules=8 " in line and "content_evaluations=8 " in line
    assert "rejected_content=3 " in line and "matches=5 " in line
    summary = [l for l in variant[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=8, invalid=0, unsupported=0), events_evaluated=1, candidates=8, detections=5" in summary


# --- evidence and reproducibility ----------------------------------------------------------------------------------------------------------------------------

def test_rules_report_and_evidence_files(run, variant):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", s) for s in range(10001, 10007)]
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t10_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
