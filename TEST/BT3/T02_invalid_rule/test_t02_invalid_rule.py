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
RULES = "TEST/BT3/T02_invalid_rule/rules.rules"            # as main.py receives it (relative to the repository root)
PRIORITY = "TEST/BT3/T02_invalid_rule/priority.rules"

# Worked out by hand from rules.rules, before running anything: line -> (status, reason, sid that can be read).
# A rule with no readable sid (malformed structure, missing or non-numeric sid) is reported with sid None.
EXPECTED_RULES = {
    2: ("valid", None, 2001),
    3: ("invalid", "invalid:malformed_rule", None),              # no closing ")"
    4: ("invalid", "invalid:malformed_rule", None),              # header only, no "("
    5: ("invalid", "invalid:missing_sid", None),
    6: ("invalid", "invalid:bad_sid", None),                     # sid:abc
    7: ("invalid", "invalid:bad_ip", 2006),                      # 300.1.1.1
    8: ("invalid", "invalid:bad_port", 2007),                    # 70000 > 65535
    9: ("invalid", "invalid:bad_port", 2008),                    # 100:50, low > high
    10: ("invalid", "invalid:bad_direction", 2009),              # <-
    11: ("invalid", "invalid:bad_option_value:content", 2010),   # |4| is an odd number of hex digits
    12: ("invalid", "invalid:depth_lt_pattern", 2011),           # depth 2 < len("ABCDE") = 5
    13: ("invalid", "invalid:within_lt_pattern", 2012),          # within 3 < len("ABCDE") = 5
    14: ("invalid", "invalid:mixed_absolute_relative", 2013),    # offset + distance on one content
    15: ("invalid", "invalid:flags_requires_tcp", 2014),         # flags on a udp rule
    16: ("invalid", "invalid:conflicting_flow", 2015),           # to_server + to_client
    17: ("invalid", "invalid:duplicate_sid", 2001),              # sid of line 2 again
}
# priority.rules: a rule with both an invalid part and an unsupported part is reported as invalid
EXPECTED_PRIORITY = {
    1: ("invalid", "invalid:missing_sid", None),                 # icmp (unsupported) but no sid  -> invalid wins
    2: ("invalid", "invalid:bad_port", 2018),                    # "drop" (unsupported) but port 99999 -> NOT unsupported:action:drop
    3: ("invalid", "invalid:depth_lt_pattern", 2019),            # pcre (unsupported keyword) but depth 2 < 5 -> NOT unsupported:keyword:pcre
}


@pytest.fixture(scope="module")
def run():
    stderr = []
    events, flows, detections, report = run_case_ids(CASE_DIR, rules=["rules.rules", "priority.rules"], stderr_out=stderr)
    # warnings.txt: the "rejected" log lines of this run, without the time stamp (so it is the same on every run)
    lines = [re.sub(r"^.*? - WARNING - ", "", line) for line in stderr[0].splitlines() if " rejected: " in line and " - WARNING - " in line]
    (CASE_DIR / "warnings.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return events, flows, detections, report, stderr[0]


def by_file(report, name):
    return {r["line"]: r for r in report if r["file"] == name}


# --- each broken rule has exactly the reason computed by hand ---------------------------------------------------

@pytest.mark.parametrize("line", sorted(EXPECTED_RULES))
def test_rules_file_line(run, line):
    status, reason, sid = EXPECTED_RULES[line]
    row = by_file(run[3], RULES)[line]
    assert (row["status"], row["reason"], row["sid"]) == (status, reason, sid)


@pytest.mark.parametrize("line", sorted(EXPECTED_PRIORITY))
def test_priority_rules_file_line(run, line):
    status, reason, sid = EXPECTED_PRIORITY[line]
    row = by_file(run[3], PRIORITY)[line]
    assert (row["status"], row["reason"], row["sid"]) == (status, reason, sid)


def test_an_invalid_rule_beats_an_unsupported_one(run):
    rows = by_file(run[3], PRIORITY)
    assert rows[2]["reason"] != "unsupported:action:drop" and rows[1]["reason"] != "unsupported:protocol:icmp"
    assert rows[3]["reason"] != "unsupported:keyword:pcre"
    assert {r["status"] for r in rows.values()} == {"invalid"} and not any(r["status"] == "unsupported" for r in run[3])


def test_every_reason_is_a_known_code_and_there_is_one_row_per_rule_line(run):
    report = run[3]
    assert len(report) == 16 + 3                                         # 16 rules in rules.rules, 3 in priority.rules
    assert [r["line"] for r in report if r["file"] == RULES] == list(range(2, 18))
    assert all(r["reason"] is None or is_valid_reason(r["reason"]) for r in report)
    assert all(r["text"] for r in report)


def test_only_the_comment_line_is_not_a_rule(run):
    assert 1 not in by_file(run[3], RULES)                                 # line 1 is the comment


# --- the engine keeps running ---------------------------------------------------------------------------------------

def test_the_valid_rule_still_produces_its_detection(run):
    _, _, detections, _, _ = run
    assert len(detections) == 1
    d = detections[0]
    assert (d["sid"], d["packet_id"], d["protocol"], d["dst_port"], d["msg"]) == (2001, 1, "TCP", 80, "T02 valid rule")
    assert d["matched"] == [{"keyword": "content", "value": "GET", "offset": 0, "length": 3}]


def test_main_py_exited_0_and_processed_the_traffic(run):
    events, flows, _, _, _ = run                                          # run_case_ids raises if main.py exits non-zero
    assert len(events) == 1 and events[0]["app_protocol"] == "HTTP" and len(flows) == 1


def test_one_warning_per_rejected_rule(run):
    stderr = run[4]
    warnings = re.findall(r"rule (\S+):(\d+) rejected: (\S+)", stderr)
    expected = ([(RULES, str(line), EXPECTED_RULES[line][1]) for line in sorted(EXPECTED_RULES) if EXPECTED_RULES[line][0] == "invalid"]
                + [(PRIORITY, str(line), EXPECTED_PRIORITY[line][1]) for line in sorted(EXPECTED_PRIORITY)])
    assert sorted(warnings) == sorted(expected)
    assert len(warnings) == 18 == len(set(warnings))                     # 15 + 3, none twice, none for the valid rule
    assert not any("rule %s:2 " % RULES in line for line in stderr.splitlines())      # the valid rule (line 2) gets no warning


def test_warnings_txt_holds_exactly_the_rejected_lines_without_time_stamps(run):
    lines = (CASE_DIR / "warnings.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 18
    assert lines[0] == f"rule {RULES}:3 rejected: invalid:malformed_rule"
    assert lines[-1] == f"rule {PRIORITY}:3 rejected: invalid:depth_lt_pattern"
    assert all(re.fullmatch(r"rule \S+:\d+ rejected: \S+", line) for line in lines)       # no time stamp, no level
    assert not any(str(ROOT) in line for line in lines)


def test_the_summary_line_counts_the_rules(run):
    summary = [line for line in run[4].splitlines() if "System shutdown complete" in line][-1]
    assert "rules(loaded=1, invalid=18, unsupported=0)" in summary and "detections=1" in summary


# --- the same file seen without a pcap ---------------------------------------------------------------------------------------

def test_run_rules_only_gives_the_same_classification_and_counters():
    report, records, rules = run_rules_only(CASE_DIR / "rules.rules")
    assert {r.line: (r.status, r.reason, r.sid) for r in records} == EXPECTED_RULES
    assert [r.sid for r in rules] == [2001]
    assert (report.total_lines, report.comment, report.blank, report.rule_lines) == (17, 1, 0, 16)
    assert (report.valid, report.invalid, report.unsupported, report.disabled) == (1, 15, 0, 0)
    assert report.rule_lines == report.valid + report.invalid + report.unsupported + report.disabled


def test_run_rules_only_with_both_files_counts_everything():
    report, _, rules = run_rules_only([CASE_DIR / "rules.rules", CASE_DIR / "priority.rules"])
    assert (report.total_lines, report.rule_lines, report.valid, report.invalid, report.unsupported) == (20, 19, 1, 18, 0)
    assert [r.sid for r in rules] == [2001]


# --- evidence and reproducibility -----------------------------------------------------------------------------------------------

def test_evidence_files_are_in_the_case_directory(run):
    for name in ("events", "flows", "detections", "rules_report"):
        assert (CASE_DIR / f"{name}.jsonl").is_file()
    text = (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")
    assert str(ROOT) not in text                                          # relative paths only


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t02_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
