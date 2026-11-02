import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.content_matcher import find, match_chain, match_contents, relative_window
from src.pipeline.pipeline import _parse_packet_layers

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_more_windows"           # evidence of the second run (variants.rules on the same pcap)
ROOT = CASE_DIR.parents[2]

P1 = b"AAA-BBB-CCC-BBB"        # 15 bytes:  AAA 0..3  - 3  BBB 4..7  - 7  CCC 8..11  - 11  BBB 12..15
P2 = b"BBB----BBB-CCC"         # 14 bytes:  BBB 0..3  ---- 3..7  BBB 7..10  - 10  CCC 11..14

# --- worked out by hand BEFORE running anything ------------------------------------------------------------------------------
# A relative content is searched from where the previous content's match ENDED (+ distance), in a window of size `within`.
# Rules 11001-11003 go to the packet to port 9001, rule 11004 to the packet to port 9002 (through their destination port).
#
# packet 1  AAA-BBB-CCC-BBB
#   11001  "AAA" "BBB" distance 1 within 3   AAA 0..3 -> window [4,7): BBB at 4..7 fits                     MATCH  (0, 4)
#   11002  "AAA" "CCC" distance 1 within 3   window [4,7): CCC is at 8..11, outside                         NO
#   11003  "BBB" "BBB" distance 1            first BBB 4..7 -> search from 8: the second BBB at 12          MATCH  (4, 12)
# packet 2  BBB----BBB-CCC          (backtracking)
#   11004  "BBB" "CCC" distance 1 within 3   BBB at 0 (ends 3) -> window [4,7): no CCC. Go back: BBB at 7 (ends 10)
#                                            -> window [11,14): CCC at 11..14 fits                          MATCH  (7, 11)
#   a matcher that only tried the first BBB would say NO here, which is wrong
# => 3 detections: (packet 1, 11001) (packet 1, 11003) (packet 2, 11004)
# counters: candidates 3 + 1 = 4, every candidate enters the content stage, rejected_content 1 (11002), matches 3
EXPECTED_MAIN = {11001: (1, [("AAA", 0, 3), ("BBB", 4, 3)]),
                 11002: None,
                 11003: (1, [("BBB", 4, 3), ("BBB", 12, 3)]),
                 11004: (2, [("BBB", 7, 3), ("CCC", 11, 3)])}
# variants.rules (same two packets):                                                                    expected
#   11101 packet 1  "AAA" "BBB" within 4 (no distance)   window starts at AAA's end: [3,7)  BBB 4..7 fits    MATCH (0, 4)
#   11102 packet 1  "AAA" "BBB" within 3                 window [3,6)  BBB 4..7 does not                   NO
#   11103 packet 1  "BBB" "BBB" distance 0               first BBB 4..7, from 7: BBB at 12                  MATCH (4, 12)
#   11104 packet 1  "BBB" "BBB" distance -3              first BBB 4..7, start 7-3 = 4: BBB at 4 itself     MATCH (4, 4)
#   11105 packet 1  "CCC" "AAA" distance 0               CCC 8..11, no AAA after it                         NO
#   11106 packet 1  "AAA" "CCC" distance 4 within 3      start 3+4 = 7, window [7,10): CCC 8..11 ends at 11  NO
#   11107 packet 1  "AAA" "CCC" distance 4 within 4      window [7,11): CCC 8..11 fits                      MATCH (0, 8)
#   11108 packet 2  "BBB" "CCC" distance 1               first BBB works: CCC at 11                         MATCH (0, 11)
#   11109 packet 2  "BBB" "CCC" within 3                 BBB 0: window [3,6) no; BBB 7: window [10,13), CCC ends 14  NO
#   11110 packet 2  "BBB" "BBB" d1 "CCC" d1 w3           BBB 0, BBB 7 (from 4), CCC in [11,14): fits        MATCH (0, 7, 11)
# => 6 detections: 11101 11103 11104 11107 (packet 1), 11108 11110 (packet 2); candidates 7 + 3 = 10, rejected_content 4, matches 6
EXPECTED_VARIANT = {11101: (1, [("AAA", 0, 3), ("BBB", 4, 3)]),
                    11102: None,
                    11103: (1, [("BBB", 4, 3), ("BBB", 12, 3)]),
                    11104: (1, [("BBB", 4, 3), ("BBB", 4, 3)]),
                    11105: None,
                    11106: None,
                    11107: (1, [("AAA", 0, 3), ("CCC", 8, 3)]),
                    11108: (2, [("BBB", 0, 3), ("CCC", 11, 3)]),
                    11109: None,
                    11110: (2, [("BBB", 0, 3), ("BBB", 7, 3), ("CCC", 11, 3)])}


def detail(items):
    return [{"keyword": "content", "value": value, "offset": offset, "length": length} for value, offset, length in items]


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


def rules_of(name):
    _, _, rules = run_rules_only(CASE_DIR / name)
    return {r.sid: r for r in rules}


@pytest.fixture(scope="module")
def payloads():
    return {i: _parse_packet_layers(ts, raw, i).payload for i, (ts, raw) in enumerate(read_pcap(str(CASE_DIR / "input.pcap")), start=1)}


def test_the_payloads_are_the_ones_of_the_hand_calculation(payloads):
    assert payloads == {1: P1, 2: P2}
    assert (P1.index(b"BBB"), P1.index(b"CCC"), P1.rindex(b"BBB")) == (4, 8, 12) and P2.rindex(b"BBB") == 7 and P2.index(b"CCC") == 11


# --- the main run -------------------------------------------------------------------------------------------------------------------

def test_three_detections_one_per_expected_rule(run):
    assert [(d["packet_id"], d["sid"]) for d in run[2]] == [(1, 11001), (1, 11003), (2, 11004)]


@pytest.mark.parametrize("sid", sorted(EXPECTED_MAIN))
def test_matched_positions_of_each_rule(run, sid):
    fired = {d["sid"]: d for d in run[2]}
    if EXPECTED_MAIN[sid] is None:
        assert sid not in fired
    else:
        packet, items = EXPECTED_MAIN[sid]
        assert fired[sid]["packet_id"] == packet and fired[sid]["matched"] == detail(items)


def test_the_backtracking_detection_reports_the_second_bbb(run):
    d = next(d for d in run[2] if d["sid"] == 11004)
    assert [(m["value"], m["offset"]) for m in d["matched"]] == [("BBB", 7), ("CCC", 11)]       # BBB = 7, not 0


def test_a_matcher_that_only_tried_the_first_bbb_would_get_rule_4_wrong(payloads):
    rule = rules_of("rules.rules")[11004]
    first, second = rule.contents
    assert find(payloads[2], first.pattern) == 0                                   # the first BBB
    start, end = relative_window(second, 0 + len(first.pattern))                   # ... gives the window [4, 7)
    assert (start, end) == (4, 7) and find(payloads[2], second.pattern, False, start, end) == -1
    assert match_chain(payloads[2], rule.contents) == [(7, 3), (11, 3)]            # the real matcher goes back and finds BBB at 7


def test_rule_2_misses_because_ccc_is_outside_the_window(payloads):
    rule = rules_of("rules.rules")[11002]
    aaa, ccc = rule.contents
    assert relative_window(ccc, len(aaa.pattern)) == (4, 7)                        # AAA ends at 3: distance 1, within 3
    assert find(payloads[1], b"CCC") == 8 and match_contents(rule, payloads[1]) is None


def test_counters(run):
    line = engine_line(run[4])
    assert "events_evaluated=2 " in line and "candidate_rules=4 " in line
    assert "rejected_header=0 " in line and "rejected_flow=0 " in line and "rejected_packet=0 " in line
    assert "content_evaluations=4 " in line and "rejected_content=1 " in line and "matches=3 " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=4, invalid=0, unsupported=0), events_evaluated=2, candidates=4, detections=3" in summary


def test_the_two_packets_are_tcp_to_ports_without_a_parser(run):
    assert [(e["dst_port"], e["app_protocol"], e["status"]) for e in run[0]] == [(9001, "UNKNOWN", "OK"), (9002, "UNKNOWN", "OK")]


# --- variant: more windows ----------------------------------------------------------------------------------------------------------------

def test_variant_detections(variant):
    got = [(d["packet_id"], d["sid"], d["matched"]) for d in variant[2]]
    expected = [(packet, sid, detail(items)) for sid, entry in sorted(EXPECTED_VARIANT.items()) if entry
                for packet, items in [entry]]
    assert got == sorted(expected, key=lambda t: (t[0], t[1]))
    assert [d["sid"] for d in variant[2]] == [11101, 11103, 11104, 11107, 11108, 11110]


@pytest.mark.parametrize("sid", sorted(EXPECTED_VARIANT))
def test_variant_each_rule_directly(payloads, sid):
    rule = rules_of("variants.rules")[sid]
    entry = EXPECTED_VARIANT[sid]
    packet = 1 if sid <= 11107 else 2
    assert match_contents(rule, payloads[packet]) == (detail(entry[1]) if entry else None)


def test_variant_negative_distance_may_overlap_the_previous_match(variant):
    d = next(d for d in variant[2] if d["sid"] == 11104)
    assert [m["offset"] for m in d["matched"]] == [4, 4]


def test_variant_counters(variant):
    line = engine_line(variant[4])
    assert "candidate_rules=10 " in line and "content_evaluations=10 " in line
    assert "rejected_content=4 " in line and "matches=6 " in line and "rule_errors=0" in line
    summary = [l for l in variant[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=10, invalid=0, unsupported=0), events_evaluated=2, candidates=10, detections=6" in summary


# --- evidence and reproducibility ---------------------------------------------------------------------------------------------------------------

def test_rules_report_and_evidence_files(run, variant):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", s) for s in (11001, 11002, 11003, 11004)]
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t11_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
