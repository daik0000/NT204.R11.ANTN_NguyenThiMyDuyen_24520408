import copy
import hashlib
import inspect

import pytest

import case_runner as cr
from pcap_builder import tcp_packet, write_pcap
from src.models.rule import Rule
from src.models.rule_report import LoadReport

GET = b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"
HEAD = "alert tcp any any -> any 80"


def rule(sid, options=""):
    return f'{HEAD} (msg:"r{sid}"; {options} sid:{sid};)'


def make_pcap(path):
    frames = [
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "S", ts=1.0),
        tcp_packet("10.0.0.2", 80, "10.0.0.1", 40000, "SA", ts=1.1),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "A", ts=1.2),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "PA", ts=1.3, payload=GET),
    ]
    return write_pcap(frames, str(path))


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "T99_case"
    d.mkdir()
    make_pcap(d / "input.pcap")
    (d / "rules.rules").write_text(rule(10, 'content:"../";') + "\n" + "not a rule\n" + rule(20, "flags:S;") + "\n",
                                   encoding="utf-8")
    return d


# --- the old runners are untouched -------------------------------------------------------------------------------------------

def params(fn):
    return [(name, p.default) for name, p in inspect.signature(fn).parameters.items()]


def test_run_case_and_run_events_keep_their_signatures():
    empty = inspect.Parameter.empty
    assert params(cr.run_case) == [("case_dir", empty), ("config_path", None), ("pcap_name", "input.pcap"),
                                   ("timeout", 120.0)]
    assert params(cr.run_events) == [("events", empty), ("cfg", None)]


def test_run_case_still_returns_just_events_and_flows(case):
    result = cr.run_case(case)
    assert isinstance(result, tuple) and len(result) == 2 and len(result[0]) == 4


# --- run_case_ids ------------------------------------------------------------------------------------------------------------------

def test_returns_events_flows_detections_and_the_rule_report(case):
    events, flows, detections, report = cr.run_case_ids(case)
    assert len(events) == 4 and len(flows) == 1
    assert [(d["sid"], d["packet_id"]) for d in detections] == [(20, 1), (10, 4)]
    assert [(r["line"], r["status"]) for r in report] == [(1, "valid"), (2, "invalid"), (3, "valid")]


def test_the_four_files_are_left_next_to_the_pcap_as_evidence(case):
    cr.run_case_ids(case)
    for name in ("events", "flows", "detections", "rules_report"):
        assert (case / f"{name}.jsonl").is_file()
    assert not (case / "settings.yaml").exists() and not (case / "output").exists()      # nothing else is left behind


def test_old_outputs_are_deleted_first(case):
    for name in ("events", "flows", "detections", "rules_report"):
        (case / f"{name}.jsonl").write_text('{"stale": true}\n', encoding="utf-8")
    events, flows, detections, report = cr.run_case_ids(case)
    for rows in (events, flows, detections, report):
        assert all("stale" not in r for r in rows)


def test_two_runs_do_not_accumulate_and_give_the_same_result(case):
    first = cr.run_case_ids(case)
    second = cr.run_case_ids(case)
    assert first == second and len(second[2]) == 2


def test_cli_path_is_relative_to_the_repository_root_when_inside_it(tmp_path):
    assert cr._cli_path(cr.ROOT / "TEST" / "BT3" / "T01" / "rules.rules") == "TEST/BT3/T01/rules.rules"
    assert cr._cli_path(str(cr.ROOT / "a.rules")) == "a.rules"
    outside = tmp_path / "x.rules"
    assert cr._cli_path(outside) == str(outside)


def test_the_sample_rules_of_the_config_are_never_loaded(case):
    _, _, detections, report = cr.run_case_ids(case)
    assert {r["file"] for r in report} == {str(case / "rules.rules")}
    assert {d["sid"] for d in detections} == {10, 20}                    # not the 1000001.. of config/rules/local.rules


def test_by_default_every_rules_file_of_the_case_is_used_in_name_order(case):
    (case / "a_first.rules").write_text(rule(30, 'content:"GET";') + "\n", encoding="utf-8")
    _, _, detections, report = cr.run_case_ids(case)
    assert [r["file"].rsplit("/", 1)[-1] for r in report] == ["a_first.rules", "rules.rules", "rules.rules", "rules.rules"]
    assert [d["sid"] for d in detections if d["packet_id"] == 4] == [30, 10]


def test_explicit_rules_may_be_a_name_a_path_or_a_list(case):
    other = case / "other.rules"
    other.write_text(rule(40, "flags:PA;") + "\n", encoding="utf-8")
    _, _, by_name, _ = cr.run_case_ids(case, rules="other.rules")
    _, _, by_path, _ = cr.run_case_ids(case, rules=other)
    _, _, by_list, report = cr.run_case_ids(case, rules=["rules.rules", other])
    assert [d["sid"] for d in by_name] == [d["sid"] for d in by_path] == [40]
    assert [d["sid"] for d in by_list if d["packet_id"] == 4] == [10, 40]
    assert len(report) == 4


def test_an_empty_list_means_no_rules_at_all(case):
    events, flows, detections, report = cr.run_case_ids(case, rules=[])
    assert len(events) == 4 and detections == [] and report == []


def test_config_path_keeps_the_other_engine_settings(case, tmp_path):
    cfg = tmp_path / "mine.yaml"
    cfg.write_text("engine:\n  disabled_sids: [10]\n  default_priority: 7\n", encoding="utf-8")
    _, _, detections, report = cr.run_case_ids(case, config_path=cfg)
    assert [r["status"] for r in report] == ["disabled", "invalid", "valid"]
    assert [d["sid"] for d in detections] == [20] and detections[0]["priority"] == 7


def test_engine_disabled_in_the_given_config_gives_no_part_3_output(case, tmp_path):
    cfg = tmp_path / "off.yaml"
    cfg.write_text("engine:\n  enabled: false\n", encoding="utf-8")
    events, _, detections, report = cr.run_case_ids(case, config_path=cfg)
    assert len(events) == 4 and detections == [] and report == []
    assert not (case / "detections.jsonl").exists()


def test_a_missing_rules_file_raises_with_the_message(case):
    with pytest.raises(RuntimeError, match="not found"):
        cr.run_case_ids(case, rules=["nope.rules"])


def test_check_false_returns_what_exists_after_a_failure(case):
    events, flows, detections, report = cr.run_case_ids(case, rules=["nope.rules"], check=False)
    assert (events, flows, detections, report) == ([], [], [], [])


def test_the_pcap_is_not_modified_and_is_deterministic(tmp_path):
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    make_pcap(a)
    make_pcap(b)
    assert hashlib.md5(a.read_bytes()).hexdigest() == hashlib.md5(b.read_bytes()).hexdigest()


# --- run_rules_only ---------------------------------------------------------------------------------------------------------------------

def test_run_rules_only_returns_report_records_and_rules(tmp_path):
    f = tmp_path / "x.rules"
    f.write_text("# comment\n" + rule(1, 'content:"a";') + "\ngarbage\n"
                 + 'alert icmp any any -> any any (msg:"i"; sid:3;)\n' + rule(4) + "\n", encoding="utf-8")
    report, records, rules = cr.run_rules_only(f)
    assert isinstance(report, LoadReport) and all(isinstance(r, Rule) for r in rules)
    assert (report.valid, report.invalid, report.unsupported, report.disabled) == (2, 1, 1, 0)
    assert [r.sid for r in rules] == [1, 4]
    assert [(r.line, r.status) for r in records] == [(2, "valid"), (3, "invalid"), (4, "unsupported"), (5, "valid")]
    assert report.total_lines == 5 and report.comment == 1 and report.rule_lines == 4


def test_run_rules_only_uses_the_config_but_does_not_modify_it(tmp_path):
    from src.utils.config import load_config
    f = tmp_path / "x.rules"
    f.write_text(rule(1) + "\n" + rule(2) + "\n", encoding="utf-8")
    cfg = load_config()
    cfg["engine"]["disabled_sids"] = [2]
    snapshot = copy.deepcopy(cfg)
    report, records, rules = cr.run_rules_only(str(f), cfg)
    assert [r.sid for r in rules] == [1] and report.disabled == 1 and records[1].status == "disabled"
    assert cfg == snapshot


def test_run_rules_only_accepts_several_files_and_reports_unreadable_ones(tmp_path):
    a, b = tmp_path / "a.rules", tmp_path / "b.rules"
    a.write_text(rule(1) + "\n", encoding="utf-8")
    b.write_text(rule(1) + "\n" + rule(2) + "\n", encoding="utf-8")
    report, records, rules = cr.run_rules_only([a, tmp_path / "gone.rules", b])
    assert [r.sid for r in rules] == [1, 2] and report.files_failed == 1
    assert [r.reason for r in records] == [None, "invalid:duplicate_sid", None]


def test_run_rules_only_does_not_load_the_sample_rules(tmp_path):
    f = tmp_path / "x.rules"
    f.write_text(rule(1) + "\n", encoding="utf-8")
    _, _, rules = cr.run_rules_only(f)
    assert [r.sid for r in rules] == [1]


def test_run_rules_only_empty_file(tmp_path):
    f = tmp_path / "empty.rules"
    f.write_text("", encoding="utf-8")
    report, records, rules = cr.run_rules_only(f)
    assert records == [] and rules == [] and report.to_dict() == dict.fromkeys(report.to_dict(), 0)
