import json
import logging

from src.models.rule_report import LoadReport, RuleRecord
from src.rules.report import write_report

from test_rule_loader import FakeParser, _cfg, _write  # noqa: E402
from src.rules.loader import load_rules


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f]


def test_summary_line():
    rep = LoadReport(valid=3, invalid=2, unsupported=1, disabled=0, files_failed=0)
    assert rep.summary() == "rules: loaded=3 invalid=2 unsupported=1 disabled=0 files_failed=0"
    assert LoadReport().summary() == "rules: loaded=0 invalid=0 unsupported=0 disabled=0 files_failed=0"


def test_write_report_all_statuses_with_null_reason(tmp_path):
    out = tmp_path / "sub" / "rules_report.jsonl"
    recs = [
        RuleRecord("a.rules", 1, "valid", None, 1, "alert ..."),
        RuleRecord("a.rules", 2, "invalid", "invalid:missing_sid", None, "bad"),
        RuleRecord("a.rules", 3, "unsupported", "unsupported:keyword:pcre", 3, "pcre"),
        RuleRecord("a.rules", 4, "disabled", "disabled:sid", 4, "off"),
    ]
    assert write_report(recs, str(out)) == 4
    rows = _lines(out)
    assert [r["status"] for r in rows] == ["valid", "invalid", "unsupported", "disabled"]
    assert rows[0]["reason"] is None and rows[0]["sid"] == 1
    assert list(rows[0]) == ["file", "line", "status", "reason", "sid", "text"]


def test_write_report_keeps_unicode_and_replaces_file(tmp_path):
    out = tmp_path / "r.jsonl"
    write_report([RuleRecord("a", 1, "valid", None, 1, 'msg:"tấn công"')], str(out))
    write_report([RuleRecord("a", 2, "valid", None, 2, "x")], str(out))
    assert "tấn công" not in out.read_text(encoding="utf-8")
    write_report([RuleRecord("a", 1, "valid", None, 1, 'msg:"tấn công"')], str(out))
    assert "tấn công" in out.read_text(encoding="utf-8")
    assert len(_lines(out)) == 1


def test_write_report_empty(tmp_path):
    out = tmp_path / "r.jsonl"
    assert write_report([], str(out)) == 0
    assert out.read_text() == ""


def test_loader_warns_for_each_rejected_rule(tmp_path, caplog):
    a = _write(tmp_path, "a.rules", "sid:1\nbad\nunsup\nsid:1\nsid:2\n")
    with caplog.at_level(logging.WARNING, logger="src.rules.loader"):
        _, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}], disabled_sids=[2]), FakeParser())
    msgs = [m for m in caplog.messages if "rejected" in m]
    assert msgs == [
        f"rule {a}:2 rejected: invalid:missing_sid",
        f"rule {a}:3 rejected: unsupported:keyword:pcre",
        f"rule {a}:4 rejected: invalid:duplicate_sid",
    ]
    assert rep.summary() == "rules: loaded=1 invalid=2 unsupported=1 disabled=1 files_failed=0"


def test_report_file_from_load(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\nbad\n")
    _, _, recs = load_rules(_cfg([{"path": a, "enabled": True}]), FakeParser())
    out = tmp_path / "rules_report.jsonl"
    write_report(recs, str(out))
    assert [(r["line"], r["status"]) for r in _lines(out)] == [(1, "valid"), (2, "invalid")]


def test_unserialisable_record_is_skipped_not_raised(tmp_path):
    class Bad:
        def to_dict(self):
            return {"x": object()}

    out = tmp_path / "r.jsonl"
    good = RuleRecord("a", 1, "valid", None, 1, "x")
    assert write_report([good, Bad(), good], str(out)) == 2
    assert len(_lines(out)) == 2


def test_unwritable_path_raises_oserror(tmp_path):
    import pytest
    with pytest.raises(OSError):
        write_report([], str(tmp_path))          # path is a directory
