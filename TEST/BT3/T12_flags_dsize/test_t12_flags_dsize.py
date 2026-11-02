import hashlib
import importlib.util
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.matcher import match_dsize, match_flags
from src.pipeline.pipeline import _parse_packet_layers

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_udp_and_modifiers"        # evidence of the second run (variants.rules on variants.pcap)
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything ------------------------------------------------------------------------------
# input.pcap, a TCP session to port 9003:   p1 SYN (0 bytes)   p2 SYN/ACK (0)   p3 ACK (0)
#                                           p4 PSH/ACK ("0123456789", 10 bytes)   p5 FIN/ACK (0)
#
#   sid    option                       exact / meaning                                            packets
#   12001  flags:S                      exactly SYN                                                 p1
#   12002  flags:SA                     exactly SYN+ACK                                             p2
#   12003  flags:A                      exactly ACK: NOT PSH/ACK, NOT FIN/ACK                       p3
#   12004  flags:A+                     ACK set, anything else allowed                              p2 p3 p4 p5
#   12005  flags:SF*                    SYN or FIN set                                              p1 p2 p5
#   12006  flags:PA; dsize:10           exactly PSH+ACK and exactly 10 bytes                        p4
#   12007  dsize:0                      empty payload                                               p1 p2 p3 p5
#   12008  dsize:<5                     fewer than 5 bytes                                          p1 p2 p3 p5
#   12009  dsize:10                     exactly 10 bytes                                            p4
#   12010  dsize:>0                     at least 1 byte                                             p4
#   12011  dsize:5<>15                  5 to 15 bytes, ends included                                p4
# => 1 + 1 + 1 + 4 + 3 + 1 + 4 + 4 + 1 + 1 + 1 = 22 detections.
# All 11 rules have the header "tcp any any <> any 9003" (both directions, so the server's SYN/ACK passes it too) and no
# content, so every rule is a candidate of every packet: candidates 11 x 5 = 55, nothing fails the header or flow,
# the 33 candidates that do not fire fail the packet stage (flags or dsize), content_evaluations 0.
EXPECTED = {12001: [1], 12002: [2], 12003: [3], 12004: [2, 3, 4, 5], 12005: [1, 2, 5], 12006: [4],
            12007: [1, 2, 3, 5], 12008: [1, 2, 3, 5], 12009: [4], 12010: [4], 12011: [4]}
TOTAL = 22

# variants.pcap = the same 5 TCP packets + p6, a UDP datagram with the same 10 bytes (a UDP packet has no flags).
#   12101  alert ip   flags:S                    p1                  (an ip rule applies to TCP; the UDP packet has no flags: NO MATCH)
#   12102  alert udp  flags:S                    INVALID: flags_requires_tcp, the rule is not loaded
#   12103  alert udp  dsize:10                   p6                  (dsize works on UDP)
#   12104  alert ip   flags:0 (no flag at all)   none                (every TCP packet has a flag; the UDP packet's flags are unknown)
#   12105  alert tcp  flags:!S  (SYN not set)    p3 p4 p5            (p2 SYN/ACK contains SYN)
#   12106  alert tcp  flags:FA                   p5
#   12107  alert tcp  flags:PA+                  p4
#   12108  alert tcp  flags:SA* (SYN or ACK)     p1 p2 p3 p4 p5
#   12109  alert tcp  dsize:>9; flags:A+         p4
#   12110  alert ip   dsize:10                   p4 p6               (an ip rule applies to TCP and UDP)
# => 1 + 1 + 0 + 3 + 1 + 1 + 5 + 1 + 2 = 15 detections; candidates: 5 TCP packets x (5 tcp + 3 ip rules) + the UDP packet x (1 udp + 3 ip) = 44;
#    rejected_packet = 44 - 15 = 29.
EXPECTED_VARIANT = {12101: [1], 12103: [6], 12104: [], 12105: [3, 4, 5], 12106: [5], 12107: [4], 12108: [1, 2, 3, 4, 5],
                    12109: [4], 12110: [4, 6]}
TOTAL_VARIANT = 15


def per_sid(detections):
    out = {}
    for d in detections:
        out.setdefault(d["sid"], []).append(d["packet_id"])
    return out


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
    out = run_case_ids(VARIANT_DIR, rules=[CASE_DIR / "variants.rules"], pcap_name="../variants.pcap", stderr_out=stderr)
    return out + (stderr[0],)


# --- every rule fires on exactly the packets of the table ---------------------------------------------------------------------------

@pytest.mark.parametrize("sid", sorted(EXPECTED))
def test_packets_matched_by_each_rule(run, sid):
    assert per_sid(run[2]).get(sid, []) == EXPECTED[sid]


def test_total_detections_and_order(run):
    detections = run[2]
    assert len(detections) == TOTAL == sum(len(v) for v in EXPECTED.values())
    keys = [(d["packet_id"], d["sid"]) for d in detections]
    assert keys == sorted(keys)                                           # packet by packet, and in rule order inside a packet


def test_flags_a_exact_is_not_flags_a_plus(run):
    by_sid = per_sid(run[2])
    assert by_sid[12003] == [3]                                           # only the bare ACK
    assert by_sid[12004] == [2, 3, 4, 5]                                  # every packet with ACK set
    assert 4 not in by_sid[12003] and 5 not in by_sid[12003]              # PSH/ACK and FIN/ACK are not "exactly ACK"


def test_dsize_boundaries(run):
    by_sid = per_sid(run[2])
    assert by_sid[12011] == [4]                                           # 10 is inside 5<>15
    assert by_sid[12008] == [1, 2, 3, 5] and by_sid[12010] == [4]         # <5 and >0 split the packets with no overlap


def test_each_detection_carries_a_header_marker(run):
    assert all(d["matched"] == [{"keyword": "header"}] for d in run[2])


def test_counters(run):
    line = engine_line(run[4])
    assert "events_evaluated=5 " in line and "candidate_rules=55 " in line
    assert "rejected_header=0 " in line and "rejected_flow=0 " in line and "rejected_packet=33 " in line
    assert "content_evaluations=0 " in line and "matches=22 " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=11, invalid=0, unsupported=0), events_evaluated=5, candidates=55, detections=22" in summary


def test_the_packets_are_what_the_hand_table_assumes(run):
    flags = [e["transport_fields"]["flags"] for e in run[0]]
    assert flags == [["SYN"], ["SYN", "ACK"], ["ACK"], ["PSH", "ACK"], ["FIN", "ACK"]]
    assert [e["raw_length"] - 54 for e in run[0]] == [0, 0, 0, 10, 0]      # 14 + 20 + 20 bytes of headers, then the payload


# --- the matchers on the real packets, without main.py ------------------------------------------------------------------------------------

def test_matchers_directly_on_the_real_packets():
    events = [_parse_packet_layers(ts, raw, i) for i, (ts, raw) in enumerate(read_pcap(str(CASE_DIR / "input.pcap")), start=1)]
    _, _, rules = run_rules_only(CASE_DIR / "rules.rules")
    by_sid = {r.sid: r for r in rules}
    for sid, packets in EXPECTED.items():
        rule = by_sid[sid]
        fired = [e.packet_id for e in events if match_flags(rule.flags, e) and match_dsize(rule.dsize, e)]
        assert fired == packets, sid


# --- variant: ip rules, UDP, more modifiers -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sid", sorted(EXPECTED_VARIANT))
def test_variant_packets_matched_by_each_rule(variant, sid):
    assert per_sid(variant[2]).get(sid, []) == EXPECTED_VARIANT[sid]


def test_variant_total(variant):
    assert len(variant[2]) == TOTAL_VARIANT == sum(len(v) for v in EXPECTED_VARIANT.values())


def test_variant_flags_on_a_udp_rule_is_invalid_and_not_loaded(variant):
    rows = {r["sid"]: r for r in variant[3]}
    assert (rows[12102]["status"], rows[12102]["reason"]) == ("invalid", "invalid:flags_requires_tcp")
    assert 12102 not in {d["sid"] for d in variant[2]}
    assert sum(r["status"] == "valid" for r in variant[3]) == 9
    warnings = re.findall(r"rule (\S+):(\d+) rejected: (\S+)", variant[4])
    assert len(warnings) == 1 and warnings[0][2] == "invalid:flags_requires_tcp"


def test_variant_a_udp_datagram_never_matches_flags_but_matches_dsize(variant):
    fired_on_udp = {d["sid"] for d in variant[2] if d["packet_id"] == 6}
    assert fired_on_udp == {12103, 12110}                                  # both dsize rules; no flags rule
    assert all(d["protocol"] == "UDP" for d in variant[2] if d["packet_id"] == 6)


def test_variant_ip_rule_with_flags_applies_to_tcp_only_in_effect(variant):
    assert per_sid(variant[2])[12101] == [1]


def test_variant_counters(variant):
    line = engine_line(variant[4])
    assert "events_evaluated=6 " in line and "candidate_rules=44 " in line
    assert "rejected_packet=29 " in line and "matches=15 " in line and "content_evaluations=0 " in line and "rule_errors=0" in line
    summary = [l for l in variant[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=9, invalid=1, unsupported=0), events_evaluated=6, candidates=44, detections=15" in summary


# --- evidence and reproducibility ----------------------------------------------------------------------------------------------------------------

def test_rules_report_and_evidence_files(run, variant):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", s) for s in range(12001, 12012)]
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_the_pcaps_are_reproducible():
    spec = importlib.util.spec_from_file_location("t12_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    for name, packets in (("input.pcap", module.PACKETS), ("variants.pcap", module.VARIANT_PACKETS)):
        rebuilt = Path(write_pcap(packets, str(CASE_DIR / "_rebuilt.pcap")))
        try:
            assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / name).read_bytes()).hexdigest()
        finally:
            rebuilt.unlink(missing_ok=True)
