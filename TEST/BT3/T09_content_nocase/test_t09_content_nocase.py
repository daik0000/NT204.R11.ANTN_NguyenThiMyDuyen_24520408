import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.content_matcher import find, match_contents
from src.pipeline.pipeline import _parse_packet_layers

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_capitals"                # evidence of the second run (variants.pcap)
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything ------------------------------------------------------------------------------
# Rules (all "alert tcp any any -> any 80"):
#   9001 content:"admin"                 9002 content:"admin"; nocase;          9003 content:"Admin"
#   9004 content:"|47 45 54|"  (GET)     9005 content:"GE|54|"; nocase;  (the bytes G E then 0x54 = T  ->  GET)
#
# input.pcap, payload "GET /Admin HTTP/1.1": G E T <space> / A d m i n ...  ->  "GET" at byte 0, "Admin" at byte 5 (5 bytes)
#   9001  "admin" is not in the payload as written (A is a capital)        -> NO MATCH
#   9002  nocase: "admin" = "Admin" ignoring case, at 5                    -> MATCH  offset 5 length 5
#   9003  "Admin" is there exactly as written, at 5                        -> MATCH  offset 5 length 5
#   9004  0x47 0x45 0x54 = "GET" at 0                                      -> MATCH  offset 0 length 3
#   9005  "GE" + 0x54 = "GET", nocase, at 0                                -> MATCH  offset 0 length 3
#   => 4 detections: 9002, 9003, 9004, 9005
#
# variants.pcap, payload "GET /ADMIN HTTP/1.1": "ADMIN" at 5
#   9001 "admin" no (case) | 9002 nocase yes | 9003 "Admin" no ("ADMIN" differs) | 9004 "GET" yes | 9005 "GET" yes (it only matches the GET part)
#   => 3 detections: 9002, 9004, 9005
# Every rule has a content and nothing else, so each of the 5 candidates enters the content stage:
#   content_evaluations 5, rejected_content 1 (9001) -> matches 4      variant: rejected_content 2 (9001, 9003) -> matches 3
EXPECTED_MAIN = {9001: None,
                 9002: {"value": "admin", "offset": 5, "length": 5},
                 9003: {"value": "Admin", "offset": 5, "length": 5},
                 9004: {"value": "|47 45 54|", "offset": 0, "length": 3},
                 9005: {"value": "GE|54|", "offset": 0, "length": 3}}
EXPECTED_VARIANT = {9001: None,
                    9002: {"value": "admin", "offset": 5, "length": 5},
                    9003: None,
                    9004: {"value": "|47 45 54|", "offset": 0, "length": 3},
                    9005: {"value": "GE|54|", "offset": 0, "length": 3}}


def detail(expected):
    return None if expected is None else [{"keyword": "content", **expected}]


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


@pytest.fixture(scope="module")
def rules():
    _, _, loaded = run_rules_only(CASE_DIR / "rules.rules")
    return {r.sid: r for r in loaded}


def payload_of(pcap):
    (ts, raw), = list(read_pcap(str(pcap)))
    return _parse_packet_layers(ts, raw, 1).payload


# --- the pattern each rule is compiled to ------------------------------------------------------------------------------------------

def test_hex_and_mixed_patterns_are_compiled_to_the_bytes_of_get(rules):
    assert rules[9004].contents[0].pattern == b"GET" == bytes([0x47, 0x45, 0x54])
    assert rules[9005].contents[0].pattern == b"GET" and rules[9005].contents[0].nocase is True
    assert rules[9004].contents[0].raw == "|47 45 54|" and rules[9005].contents[0].raw == "GE|54|"
    assert [rules[s].contents[0].nocase for s in (9001, 9002, 9003)] == [False, True, False]


# --- input.pcap: GET /Admin HTTP/1.1 ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", sorted(EXPECTED_MAIN))
def test_each_rule_on_the_payload(run, sid):
    fired = {d["sid"]: d for d in run[2]}
    expected = EXPECTED_MAIN[sid]
    if expected is None:
        assert sid not in fired
    else:
        assert fired[sid]["matched"] == detail(expected)


def test_four_detections_in_rule_order(run):
    assert [d["sid"] for d in run[2]] == [9002, 9003, 9004, 9005]
    assert all(d["packet_id"] == 1 and d["protocol"] == "TCP" and d["application_protocol"] == "HTTP" for d in run[2])


def test_value_is_the_text_of_the_rule_not_of_the_packet(run):
    by_sid = {d["sid"]: d for d in run[2]}
    assert by_sid[9002]["matched"][0]["value"] == "admin"            # the packet says "Admin"
    assert by_sid[9005]["matched"][0]["value"] == "GE|54|"            # the rule text, not the decoded bytes


def test_counters(run):
    line = engine_line(run[4])
    assert "events_evaluated=1 " in line and "candidate_rules=5 " in line
    assert "rejected_header=0 " in line and "rejected_flow=0 " in line and "rejected_packet=0 " in line
    assert "content_evaluations=5 " in line and "rejected_content=1 " in line and "matches=4 " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=5, invalid=0, unsupported=0), events_evaluated=1, candidates=5, detections=4" in summary


def test_the_same_result_without_main_py(rules):
    payload = payload_of(CASE_DIR / "input.pcap")
    assert payload.startswith(b"GET /Admin HTTP/1.1")
    for sid, expected in EXPECTED_MAIN.items():
        assert match_contents(rules[sid], payload) == detail(expected), sid


def test_the_search_itself(rules):
    payload = payload_of(CASE_DIR / "input.pcap")
    assert find(payload, b"admin") == -1 and find(payload, b"admin", nocase=True) == 5
    assert find(payload, b"Admin") == 5 and find(payload, b"GET") == 0 and find(payload, b"get") == -1


# --- variant: GET /ADMIN HTTP/1.1 ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", sorted(EXPECTED_VARIANT))
def test_variant_each_rule_on_the_payload(variant, sid):
    fired = {d["sid"]: d for d in variant[2]}
    expected = EXPECTED_VARIANT[sid]
    if expected is None:
        assert sid not in fired
    else:
        assert fired[sid]["matched"] == detail(expected)


def test_variant_three_detections_and_counters(variant):
    assert [d["sid"] for d in variant[2]] == [9002, 9004, 9005]
    line = engine_line(variant[4])
    assert "candidate_rules=5 " in line and "content_evaluations=5 " in line
    assert "rejected_content=2 " in line and "matches=3 " in line
    summary = [l for l in variant[4].splitlines() if "System shutdown complete" in l][-1]
    assert "events_evaluated=1, candidates=5, detections=3" in summary


def test_variant_9004_and_9005_match_only_the_get_part(variant):
    by_sid = {d["sid"]: d["matched"][0] for d in variant[2]}
    assert (by_sid[9004]["offset"], by_sid[9004]["length"]) == (0, 3) == (by_sid[9005]["offset"], by_sid[9005]["length"])


def test_variant_without_main_py(rules):
    payload = payload_of(CASE_DIR / "variants.pcap")
    assert payload.startswith(b"GET /ADMIN HTTP/1.1")
    for sid, expected in EXPECTED_VARIANT.items():
        assert match_contents(rules[sid], payload) == detail(expected), sid


# --- evidence and reproducibility ---------------------------------------------------------------------------------------------------------------------

def test_rules_report_and_evidence_files(run, variant):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", s) for s in range(9001, 9006)]
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_the_pcaps_are_reproducible():
    spec = importlib.util.spec_from_file_location("t09_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    for name, packets in (("input.pcap", module.PACKETS), ("variants.pcap", module.VARIANT_PACKETS)):
        rebuilt = Path(write_pcap(packets, str(CASE_DIR / "_rebuilt.pcap")))
        try:
            assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / name).read_bytes()).hexdigest()
        finally:
            rebuilt.unlink(missing_ok=True)
