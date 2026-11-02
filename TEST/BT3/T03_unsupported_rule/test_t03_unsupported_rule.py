import hashlib
import importlib.util
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.models.rule_report import is_valid_reason

CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[2]
RULES = "TEST/BT3/T03_unsupported_rule/rules.rules"       # as main.py receives it (relative to the repository root)

# Worked out by hand from rules.rules, before running anything: line -> (status, reason, sid).
# Every one of these rules is well-formed, so the sid is always readable.
EXPECTED = {
    2: ("valid", None, 3001),
    3: ("unsupported", "unsupported:keyword:pcre", 3002),
    4: ("unsupported", "unsupported:keyword:byte_test", 3003),
    5: ("unsupported", "unsupported:keyword:flowbits", 3004),
    6: ("unsupported", "unsupported:keyword:threshold", 3005),
    7: ("unsupported", "unsupported:keyword:http_uri", 3006),
    8: ("unsupported", "unsupported:content_negation", 3007),
    9: ("unsupported", "unsupported:protocol:icmp", 3008),
    10: ("unsupported", "unsupported:action:drop", 3009),
    11: ("unsupported", "unsupported:ip_syntax", 3010),          # $HOME_NET
    12: ("unsupported", "unsupported:ip_syntax", 3011),          # [10.0.0.1,10.0.0.2]
    13: ("unsupported", "unsupported:ip_syntax", 3012),          # !10.0.0.1
    14: ("unsupported", "unsupported:port_syntax", 3013),        # [80,443]
    15: ("unsupported", "unsupported:flow_option:stateless", 3014),
    16: ("valid", None, 3015),                                   # reference + metadata are accepted (stored only)
    17: ("unsupported", "unsupported:flags_mask", 3016),         # flags:SA,12
}
VALID_SIDS = [3001, 3015]

# Would the rule fire if its unsupported part were simply ignored? Worked out by hand for the packet
# (TCP 10.0.0.1:40003 -> 10.0.0.2:80, flags PSH+ACK, payload "GET /index.html HTTP/1.1..."):
# line -> (old text, text with the unsupported part ignored). Every line is "yes" except 9 (icmp), a TCP packet
# can never match an icmp rule, so line 9 gives no evidence from the packet.
IGNORED_VERSION = {
    3: ('pcre:"/etc/passwd/i"; ', ""),
    4: ("byte_test:2,>,5,0; ", ""),
    5: ("flowbits:set,x; ", ""),
    6: ("threshold:type limit, track by_src, count 1, seconds 60; ", ""),
    7: ("http_uri; ", ""),
    8: ('content:!"x"; ', ""),                       # no content left: header-only rule
    10: ("drop tcp", "alert tcp"),                   # the action is ignored
    11: ("$HOME_NET", "any"),                        # an unresolved variable read as "any"
    12: ("[10.0.0.1,10.0.0.2]", "any"),
    13: ("!10.0.0.1", "any"),                        # (read literally, "!10.0.0.1" would NOT match this packet from 10.0.0.1)
    14: ("[80,443]", "any"),
    15: ("flow:stateless; ", ""),
    17: ("flags:PA,12;", "flags:PA;"),               # the mask is ignored: exact PA, and the packet is PSH+ACK
}
NO_NEGATIVE_EVIDENCE = [9]                           # icmp rule, TCP packet


@pytest.fixture(scope="module")
def run():
    stderr = []
    events, flows, detections, report = run_case_ids(CASE_DIR, rules=["rules.rules"], stderr_out=stderr)
    lines = [re.sub(r"^.*? - WARNING - ", "", line) for line in stderr[0].splitlines()
             if " rejected: " in line and " - WARNING - " in line]
    (CASE_DIR / "warnings.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return events, flows, detections, report, stderr[0]


# --- each unsupported rule has exactly the reason computed by hand --------------------------------------------------

@pytest.mark.parametrize("line", sorted(EXPECTED))
def test_rules_file_line(run, line):
    status, reason, sid = EXPECTED[line]
    row = {r["line"]: r for r in run[3]}[line]
    assert (row["status"], row["reason"], row["sid"]) == (status, reason, sid)


def test_nothing_is_invalid_and_every_reason_is_a_known_code(run):
    report = run[3]
    assert len(report) == 16 and [r["line"] for r in report] == list(range(2, 18))
    assert {r["status"] for r in report} == {"valid", "unsupported"}
    assert all(r["reason"] is None or is_valid_reason(r["reason"]) for r in report)


def test_reference_and_metadata_are_accepted_and_only_stored():
    _, records, rules = run_rules_only(CASE_DIR / "rules.rules")
    assert {r.line: r.status for r in records}[16] == "valid"
    rule = next(r for r in rules if r.sid == 3015)
    assert rule.passive_options == (("reference", "url,example.com/t03"), ("metadata", "service http"))


# --- no crash, and the valid rules still match ----------------------------------------------------------------------------

def test_main_py_exited_0_and_processed_the_traffic(run):
    events, flows, _, _, _ = run                                          # run_case_ids raises if main.py exits non-zero
    assert len(events) == 1 and events[0]["app_protocol"] == "HTTP" and len(flows) == 1


def test_only_the_two_valid_rules_fire(run):
    _, _, detections, _, _ = run
    assert [d["sid"] for d in detections] == VALID_SIDS                   # in rule order
    assert all(d["packet_id"] == 1 and d["protocol"] == "TCP" and d["dst_port"] == 80 for d in detections)
    assert detections[0]["matched"] == [{"keyword": "content", "value": "GET", "offset": 0, "length": 3}]
    assert detections[1]["matched"] == [{"keyword": "content", "value": "HTTP", "offset": 16, "length": 4}]
    assert detections[1]["msg"] == "T03 reference and metadata"


def test_an_unsupported_rule_never_fires(run):
    fired = {d["sid"] for d in run[2]}
    assert fired.isdisjoint({sid for _, (status, _, sid) in EXPECTED.items() if status == "unsupported"})


def test_the_absence_of_those_detections_is_real_evidence(tmp_path):
    """
    "No unsupported rule fires" only proves something if the rule WOULD fire once its unsupported part is
    ignored. Check it by running that ignored version of every such rule against the same packet.
    """
    lines = (CASE_DIR / "rules.rules").read_text(encoding="utf-8").splitlines()
    ignored = []
    for line_no, (old, new) in sorted(IGNORED_VERSION.items()):
        original = lines[line_no - 1]
        assert old in original, f"line {line_no}: {old!r} not in the rule"
        ignored.append(original.replace(old, new, 1))
    case = tmp_path / "ignored"
    case.mkdir()
    (case / "input.pcap").write_bytes((CASE_DIR / "input.pcap").read_bytes())
    (case / "ignored.rules").write_text("\n".join(ignored) + "\n", encoding="utf-8")
    _, _, detections, report = run_case_ids(case)
    assert {r["status"] for r in report} == {"valid"}                     # the ignored versions are plain valid rules
    expected = [EXPECTED[line][2] for line in sorted(IGNORED_VERSION)]
    assert [d["sid"] for d in detections] == expected                     # ... and every one of them fires


def test_the_icmp_rule_is_the_one_case_without_evidence_from_the_packet():
    assert NO_NEGATIVE_EVIDENCE == [9] and EXPECTED[9][1] == "unsupported:protocol:icmp"
    assert sorted(set(range(3, 18)) - {16} - set(IGNORED_VERSION)) == NO_NEGATIVE_EVIDENCE


# --- warnings ----------------------------------------------------------------------------------------------------------------------

def test_one_warning_per_unsupported_rule(run):
    warnings = re.findall(r"rule (\S+):(\d+) rejected: (\S+)", run[4])
    expected = [(RULES, str(line), reason) for line, (status, reason, _) in sorted(EXPECTED.items()) if status == "unsupported"]
    assert sorted(warnings) == sorted(expected)
    assert len(warnings) == 14 == len(set(warnings))                      # none twice, none for the 2 valid rules


def test_warnings_txt_holds_the_rejected_lines_without_time_stamps(run):
    lines = (CASE_DIR / "warnings.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 14
    assert lines[0] == f"rule {RULES}:3 rejected: unsupported:keyword:pcre"
    assert lines[-1] == f"rule {RULES}:17 rejected: unsupported:flags_mask"
    assert all(re.fullmatch(r"rule \S+:\d+ rejected: \S+", line) for line in lines)
    assert not any(str(ROOT) in line for line in lines)


def test_the_summary_line_counts_the_rules(run):
    summary = [line for line in run[4].splitlines() if "System shutdown complete" in line][-1]
    assert "rules(loaded=2, invalid=0, unsupported=14)" in summary and "detections=2" in summary


# --- counters without a pcap --------------------------------------------------------------------------------------------------------

def test_run_rules_only_gives_the_same_classification_and_counters():
    report, records, rules = run_rules_only(CASE_DIR / "rules.rules")
    assert {r.line: (r.status, r.reason, r.sid) for r in records} == EXPECTED
    assert [r.sid for r in rules] == VALID_SIDS
    assert (report.total_lines, report.comment, report.blank, report.rule_lines) == (17, 1, 0, 16)
    assert (report.valid, report.invalid, report.unsupported, report.disabled) == (2, 0, 14, 0)
    assert report.rule_lines == report.valid + report.invalid + report.unsupported + report.disabled


# --- evidence and reproducibility --------------------------------------------------------------------------------------------------

def test_evidence_files_are_in_the_case_directory(run):
    for name in ("events", "flows", "detections", "rules_report"):
        assert (CASE_DIR / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t03_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
