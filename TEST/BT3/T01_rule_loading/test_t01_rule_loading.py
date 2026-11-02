import copy
import hashlib
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.rules.loader import load_rules
from src.rules.repository import RuleRepository
from src.rules.validator import parse_rule
from src.utils.config import load_config

CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[2]
RULES = CASE_DIR / "rules.rules"
DISABLED = CASE_DIR / "disabled.rules"
VARIANT_DIR = CASE_DIR / "variant_disabled_sids"          # evidence of the disabled_sids variant, from main.py
REPORTED_FILE = str(RULES.relative_to(ROOT))              # main.py got the path relative to the repository root

# Worked out by hand from rules.rules (11 physical lines, line 10 continues line 9):
#   comments (4): lines 1, 2, 5 (indented) and 8 (a commented-out rule)
#   blanks   (3): lines 3, 6 and 7 (spaces only)
#   rules    (3): line 4 (sid 1001), lines 9+10 joined (sid 1002), line 11 (sid 1003)
#   logical lines = 4 + 3 + 3 = 10
RULE_LINE_NUMBERS = [4, 9, 11]
JOINED_RULE_1002 = 'alert tcp any any -> any 80 (msg:"T01 rule 1002"; content:"POST"; sid:1002;)'


def make_cfg(disabled_sids=()):
    cfg = load_config()
    cfg["engine"]["rule_files"] = [{"path": str(RULES), "enabled": True}, {"path": str(DISABLED), "enabled": False}]
    cfg["engine"]["disabled_sids"] = list(disabled_sids)
    return cfg


class CountingParser:
    """Stands in for parse_fn and records every call, to show what reaches the parser."""

    def __init__(self, cfg):
        self.cfg, self.calls = cfg, []

    def __call__(self, text, file, line_no):
        self.calls.append((file, line_no, text))
        return parse_rule(text, file, line_no, self.cfg)


def load(disabled_sids=()):
    cfg = make_cfg(disabled_sids)
    spy = CountingParser(cfg)
    rules, report, records = load_rules(cfg, spy)
    return spy, rules, report, records


def assert_equation(report):
    assert report.rule_lines == report.valid + report.invalid + report.unsupported + report.disabled
    assert report.total_lines == report.blank + report.comment + report.rule_lines


# --- run 1: nothing disabled -----------------------------------------------------------------------------------

def test_only_the_three_rule_lines_reach_the_parser():
    spy, _, report, _ = load()
    assert len(spy.calls) == 3 == report.rule_lines                      # comments and blanks are never parsed
    assert [line for _, line, _ in spy.calls] == RULE_LINE_NUMBERS
    assert all(file == str(RULES) for file, _, _ in spy.calls)           # and nothing from disabled.rules


def test_the_commented_out_rule_is_just_a_comment():
    spy, rules, report, records = load()
    assert "1999" not in " ".join(text for _, _, text in spy.calls)
    assert 1999 not in [r.sid for r in rules] and all(r.sid != 1999 for r in records)


def test_the_two_line_rule_is_joined_with_one_space():
    spy, _, _, records = load()
    assert spy.calls[1][2] == JOINED_RULE_1002
    assert records[1].line == 9 and records[1].text == JOINED_RULE_1002      # numbered by its first line


def test_counters_without_disabled_sids():
    _, rules, report, _ = load()
    assert (report.total_lines, report.blank, report.comment, report.rule_lines) == (10, 3, 4, 3)
    assert (report.valid, report.invalid, report.unsupported, report.disabled) == (3, 0, 0, 0)
    assert (report.files_failed, report.disabled_files) == (0, 1)
    assert_equation(report)
    assert [r.sid for r in rules] == [1001, 1002, 1003]


def test_the_disabled_file_contributes_nothing():
    spy, rules, report, records = load()
    assert 2001 not in [r.sid for r in rules]
    assert all(rec.file == str(RULES) for rec in records)
    assert report.disabled_files == 1 and report.files_failed == 0


def test_records_of_run_1():
    _, _, _, records = load()
    assert [(r.line, r.status, r.reason, r.sid) for r in records] == [
        (4, "valid", None, 1001), (9, "valid", None, 1002), (11, "valid", None, 1003)]


# --- run 2: disabled_sids: [1002] -----------------------------------------------------------------------------------

def test_a_disabled_sid_is_recorded_but_not_stored():
    _, rules, report, records = load([1002])
    repo = RuleRepository()
    for rule in rules:
        repo.add(rule)
    repo.freeze()
    assert 1002 not in repo and [r.sid for r in repo.all()] == [1001, 1003]
    disabled = records[1]
    assert (disabled.line, disabled.status, disabled.reason, disabled.sid) == (9, "disabled", "disabled:sid", 1002)
    assert [r.status for r in records] == ["valid", "disabled", "valid"]


def test_counters_with_disabled_sids():
    spy, _, report, _ = load([1002])
    assert (report.total_lines, report.blank, report.comment, report.rule_lines) == (10, 3, 4, 3)
    assert (report.valid, report.invalid, report.unsupported, report.disabled) == (2, 0, 0, 1)    # not counted in valid
    assert len(spy.calls) == 3                                           # a disabled rule was still parsed first
    assert_equation(report)


def test_a_disabled_sid_that_is_not_in_the_file_changes_nothing():
    _, rules, report, records = load([4242])
    assert report.disabled == 0 and report.valid == 3 and [r.sid for r in rules] == [1001, 1002, 1003]


# --- the same file through the real entry points --------------------------------------------------------------------

def test_run_rules_only_gives_the_same_counters():
    report, records, rules = run_rules_only(RULES)
    assert (report.total_lines, report.blank, report.comment, report.rule_lines, report.valid) == (10, 3, 4, 3, 3)
    assert [r.sid for r in rules] == [1001, 1002, 1003] and [r.line for r in records] == RULE_LINE_NUMBERS
    cfg = load_config()
    cfg["engine"]["disabled_sids"] = [1002]
    report, records, rules = run_rules_only(RULES, cfg)
    assert (report.valid, report.disabled) == (2, 1) and [r.sid for r in rules] == [1001, 1003]
    assert_equation(report)


@pytest.fixture(scope="module")
def cli():
    events, flows, detections, report = run_case_ids(CASE_DIR, rules=["rules.rules"])
    return events, flows, detections, report


def test_main_py_writes_a_rules_report_line_for_each_rule(cli):
    _, _, _, report = cli
    assert [(r["line"], r["status"], r["reason"], r["sid"]) for r in report] == [
        (4, "valid", None, 1001), (9, "valid", None, 1002), (11, "valid", None, 1003)]
    assert all(r["file"] == REPORTED_FILE for r in report)             # no absolute path of the machine in the evidence
    assert not any(str(ROOT) in line for line in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8").splitlines())
    assert report[1]["text"] == JOINED_RULE_1002
    assert all(set(r) == {"file", "line", "status", "reason", "sid", "text"} for r in report)


def test_main_py_still_processes_the_traffic(cli):
    events, flows, detections, _ = cli
    assert len(events) == 1 and events[0]["transport_protocol"] == "TCP" and len(flows) == 1
    assert detections == []                                              # the SYN matches none of the three rules


def test_evidence_files_are_in_the_case_directory(cli):
    for name in ("events", "flows", "detections", "rules_report"):
        assert (CASE_DIR / f"{name}.jsonl").is_file()


def test_main_py_with_disabled_sids_writes_a_disabled_record():
    VARIANT_DIR.mkdir(exist_ok=True)
    events, flows, detections, report = run_case_ids(
        VARIANT_DIR, rules=[RULES], config_path=CASE_DIR / "config_disabled_sids.yaml", pcap_name="../input.pcap")
    assert [(r["line"], r["status"], r["reason"], r["sid"]) for r in report] == [
        (4, "valid", None, 1001), (9, "disabled", "disabled:sid", 1002), (11, "valid", None, 1003)]
    assert all(r["file"] == REPORTED_FILE for r in report)
    assert len(events) == 1 and len(flows) == 1 and detections == []
    for name in ("events", "flows", "detections", "rules_report"):
        assert (VARIANT_DIR / f"{name}.jsonl").is_file()


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t01_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = write_pcap(module.PACKETS, str(Path(__file__).parent / "_rebuilt.pcap"))
    try:
        assert hashlib.md5(Path(rebuilt).read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        Path(rebuilt).unlink(missing_ok=True)
