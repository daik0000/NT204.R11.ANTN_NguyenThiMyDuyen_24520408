import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.engine import Engine
from src.flow.tracker import FlowTracker
from src.pipeline.pipeline import _parse_packet_layers
from src.utils.config import load_config

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_other_rules"            # evidence of the second run (variants.rules on the same pcap)
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything -----------------------------------------------------------------------------
# input.pcap:  p1 SYN   p2 SYN/ACK   p3 ACK (the flow is now ESTABLISHED)   p4 the request, sent to the server:
#   GET /../../etc/passwd HTTP/1.1      G0 E1 T2 ' '3 /4  ../ at 5..8   ../ at 8..11   "/etc/passwd" at 10..21   HTTP/1.1 at 22..30
#
#   sid     rule (all "alert tcp any any -> any 80")                          packet 4
#   100001  content:"../"                                                      MATCH  offset 5  length 3
#   100002  content:"/etc/passwd"                                              MATCH  offset 10 length 11
#   100003  flow:to_server,established; dsize:>0   (header + flow, no content) MATCH  [{"keyword": "header"}]
#   100004  content:"/etc/shadow"                                              no
# => 3 detections for the SAME packet (4), in rule order 100001, 100002, 100003. The engine does not stop at the first.
# (100003 has dsize:>0 so that it does not also fire on the pure ACK p3, which is established and sent to the server too.)
#
# Counters, packet by packet (every rule is a candidate of the three packets sent to port 80: p1, p3, p4; p2 goes to port 52133):
#   p1 SYN   not established, empty : 100001 100002 100004 enter the content stage and fail (3) | 100003 fails flow (1)
#   p3 ACK   established,    empty : 100001 100002 100004 fail in content (3)                  | 100003 passes flow, fails dsize (1 packet)
#   p4       established, 53 bytes : 100001 100002 match, 100004 fails in content (3 enter, 1 fails) | 100003 matches
#   candidates 12 | rejected_flow 1 | rejected_packet 1 | content_evaluations 9 | rejected_content 3 + 3 + 1 = 7 | matches 3   (12 = 1+1+7+3)
EXPECTED = [
    (100001, [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]),
    (100002, [{"keyword": "content", "value": "/etc/passwd", "offset": 10, "length": 11}]),
    (100003, [{"keyword": "header"}]),
]
# variants.rules on the same session (the session is ESTABLISHED at p3 and p4):
#   13101 "passwd"                                     p4  (15, 6)
#   13102 "etc" then "passwd" distance 1               p4  etc 11..14, passwd from 15: (11, 15)
#   13103 flow:to_client,established; "../"            none (the request is sent to the server)
#   13104 "../" then "../" distance 0                  p4  first ../ 5..8, second from 8: (5, 8)
#   13105 "http/1.1" nocase                            p4  (22, 8)
#   13106 dsize:>1000; "../"                           none (the payload is 53 bytes)
# => 4 detections (13101, 13102, 13104, 13105), all packet 4. candidates 6 x 3 = 18; rejected_flow 3 (13103 on p1, p3, p4);
#    rejected_packet 3 (13106); content_evaluations 12 (4 on each of p1, p3, p4); rejected_content 8 (4 + 4 on p1 and p3); matches 4
EXPECTED_VARIANT = [
    (13101, [("passwd", 15, 6)]),
    (13102, [("etc", 11, 3), ("passwd", 15, 6)]),
    (13104, [("../", 5, 3), ("../", 8, 3)]),
    (13105, [("http/1.1", 22, 8)]),
]


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


# --- three detections for one packet, in rule order ----------------------------------------------------------------------------------

def test_three_detections_for_the_same_packet_in_rule_order(run):
    detections = run[2]
    assert [d["sid"] for d in detections] == [100001, 100002, 100003]
    assert {d["packet_id"] for d in detections} == {4} and len(detections) == 3


def test_matched_details_of_each_detection(run):
    assert [(d["sid"], d["matched"]) for d in run[2]] == EXPECTED


def test_the_rule_that_does_not_match_is_absent(run):
    assert 100004 not in {d["sid"] for d in run[2]}


def test_all_three_describe_the_same_packet_and_the_same_flow(run):
    detections = run[2]
    for key in ("packet_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "application_protocol",
                "flow_id", "flow_direction"):
        assert len({d[key] for d in detections}) == 1, key
    d = detections[0]
    assert (d["src_ip"], d["src_port"], d["dst_ip"], d["dst_port"]) == ("10.0.0.5", 52133, "192.168.1.20", 80)
    assert (d["flow_direction"], d["application_protocol"], d["flow_id"] is not None) == ("to_server", "HTTP", True)
    assert [d["msg"] for d in detections] == ["T13 directory traversal", "T13 passwd file",
                                              "T13 data sent to the server on an established connection"]


def test_the_flow_is_established_when_the_request_arrives(run):
    states = [e["flow_state"] for e in run[0]]
    assert states == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED", "ESTABLISHED"]


def test_the_handshake_and_the_bare_ack_produce_no_detection(run):
    assert not any(d["packet_id"] in (1, 2, 3) for d in run[2])


def test_counters(run):
    line = engine_line(run[4])
    assert "events_evaluated=4 " in line and "candidate_rules=12 " in line
    assert "rejected_header=0 " in line and "rejected_flow=1 " in line and "rejected_packet=1 " in line
    assert "content_evaluations=9 " in line and "rejected_content=7 " in line and "matches=3 " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=4, invalid=0, unsupported=0), events_evaluated=4, candidates=12, detections=3" in summary
    assert 12 == 1 + 1 + 7 + 3                                            # every candidate ends in exactly one outcome


def test_matches_is_three_and_candidates_are_at_least_four(run):
    line = engine_line(run[4])
    candidates = int(line.split("candidate_rules=")[1].split()[0])
    matches = int(line.split("matches=")[1].split()[0])
    assert matches == 3 and candidates >= 4


# --- the engine object itself, without main.py -----------------------------------------------------------------------------------------

def test_engine_returns_every_match_and_counts_three():
    cfg = load_config()
    cfg["engine"]["rule_files"] = [{"path": str(CASE_DIR / "rules.rules"), "enabled": True}]
    tracker = FlowTracker(cfg)
    engine = Engine(cfg, tracker)
    last = []
    for pid, (ts, raw) in enumerate(read_pcap(str(CASE_DIR / "input.pcap")), start=1):
        event = _parse_packet_layers(ts, raw, pid)
        tracker.update(event)
        last = engine.process(event)
    assert [d.sid for d in last] == [100001, 100002, 100003]              # the last call returned all three, not just the first
    assert engine.stats.matches == 3 and engine.stats.candidate_rules >= 4 and engine.stats.is_consistent()


def test_rules_are_valid_and_in_file_order():
    report, records, rules = run_rules_only(CASE_DIR / "rules.rules")
    assert [r.sid for r in rules] == [100001, 100002, 100003, 100004] and report.valid == 4


# --- variant: other kinds of rule on the same packet -----------------------------------------------------------------------------------------

def test_variant_detections_in_rule_order(variant):
    assert [d["sid"] for d in variant[2]] == [s for s, _ in EXPECTED_VARIANT]
    assert {d["packet_id"] for d in variant[2]} == {4}


@pytest.mark.parametrize("sid, items", EXPECTED_VARIANT)
def test_variant_matched_positions(variant, sid, items):
    d = next(d for d in variant[2] if d["sid"] == sid)
    assert d["matched"] == [{"keyword": "content", "value": v, "offset": o, "length": n} for v, o, n in items]


def test_variant_rules_that_must_not_fire(variant):
    fired = {d["sid"] for d in variant[2]}
    assert 13103 not in fired and 13106 not in fired


def test_variant_counters(variant):
    line = engine_line(variant[4])
    assert "candidate_rules=18 " in line and "rejected_flow=3 " in line and "rejected_packet=3 " in line
    assert "content_evaluations=12 " in line and "rejected_content=8 " in line and "matches=4 " in line and "rule_errors=0" in line
    summary = [l for l in variant[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=6, invalid=0, unsupported=0), events_evaluated=4, candidates=18, detections=4" in summary


# --- evidence and reproducibility -----------------------------------------------------------------------------------------------------------------------

def test_rules_report_and_evidence_files(run, variant):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", s) for s in (100001, 100002, 100003, 100004)]
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t13_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
