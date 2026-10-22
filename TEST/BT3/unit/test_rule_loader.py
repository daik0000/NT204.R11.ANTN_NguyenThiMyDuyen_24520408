import copy
import logging

import pytest

from src.models.rule import IpSpec, PortSpec, Rule
from src.models.rule_report import ParseResult
from src.rules import loader
from src.rules.loader import load_rules
from src.utils.config import DEFAULT_CONFIG


def _rule(sid, file="", line_no=0, text=""):
    return Rule(action="alert", protocol="tcp", src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535),
                direction="->", dst_ip=IpSpec(any=True), dst_port=PortSpec(0, 65535),
                msg="m", sid=sid, source_file=file, line_no=line_no, raw=text)


class FakeParser:
    """Rule text 'sid:N' -> valid; 'bad' -> invalid; 'unsup' -> unsupported; 'boom' -> raises."""

    def __init__(self):
        self.calls = []

    def __call__(self, text, file, line_no):
        self.calls.append((text, file, line_no))
        t = text.strip()
        if t.startswith("sid:"):
            n = int(t[4:])
            return ParseResult("valid", rule=_rule(n, file, line_no, text), sid=n)
        if t == "bad":
            return ParseResult("invalid", reason="invalid:missing_sid")
        if t.startswith("bad:"):
            return ParseResult("invalid", reason="invalid:bad_ip", sid=int(t[4:]))
        if t == "unsup":
            return ParseResult("unsupported", reason="unsupported:keyword:pcre", sid=9)
        if t == "boom":
            raise RuntimeError("parser exploded")
        if t == "junk":
            return "not a ParseResult"
        raise AssertionError(t)


def _cfg(files, disabled_sids=()):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["engine"]["rule_files"] = [dict(f) for f in files]
    cfg["engine"]["disabled_sids"] = list(disabled_sids)
    return cfg


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_two_files_loaded_in_order(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\nsid:2\n")
    b = _write(tmp_path, "b.rules", "sid:3\n")
    parser = FakeParser()
    rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}, {"path": b, "enabled": True}]), parser)
    assert [r.sid for r in rules] == [1, 2, 3]
    assert (rep.valid, rep.rule_lines, rep.files_failed, rep.disabled_files) == (3, 3, 0, 0)
    assert [(r.file, r.line, r.status) for r in recs] == [(a, 1, "valid"), (a, 2, "valid"), (b, 1, "valid")]


def test_comment_and_blank_lines_never_reach_parser(tmp_path):
    a = _write(tmp_path, "a.rules", "# c\n\nsid:1\n   \n# sid:2\n")
    parser = FakeParser()
    rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}]), parser)
    assert len(parser.calls) == 1 and parser.calls[0][2] == 3
    assert (rep.total_lines, rep.blank, rep.comment, rep.rule_lines) == (5, 2, 2, 1)
    assert len(recs) == 1


def test_disabled_file_not_read(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\n")
    b = _write(tmp_path, "b.rules", "sid:2\n")
    parser = FakeParser()
    rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": False}, {"path": b, "enabled": True}]), parser)
    assert [r.sid for r in rules] == [2]
    assert rep.disabled_files == 1 and rep.files_failed == 0
    assert all(c[1] == b for c in parser.calls)


def test_disabled_sid_recorded_not_loaded(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\nsid:2\nbad:2\nunsup\n")
    rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}], disabled_sids=[2, 9]), FakeParser())
    assert [r.sid for r in rules] == [1]
    assert [(r.status, r.reason, r.sid) for r in recs] == [
        ("valid", None, 1),
        ("disabled", "disabled:sid", 2),
        ("invalid", "invalid:bad_ip", 2),                    # invalid keeps its status
        ("unsupported", "unsupported:keyword:pcre", 9),      # so does unsupported
    ]
    assert (rep.valid, rep.disabled, rep.invalid, rep.unsupported) == (1, 1, 1, 1)
    assert rep.rule_lines == rep.valid + rep.invalid + rep.unsupported + rep.disabled


def test_duplicate_sid_across_files_and_before_disable(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\nsid:5\n")
    b = _write(tmp_path, "b.rules", "sid:1\nsid:5\n")
    rules, rep, recs = load_rules(
        _cfg([{"path": a, "enabled": True}, {"path": b, "enabled": True}], disabled_sids=[5]), FakeParser())
    assert [r.sid for r in rules] == [1]
    assert [(r.status, r.reason) for r in recs] == [
        ("valid", None), ("disabled", "disabled:sid"),
        ("invalid", "invalid:duplicate_sid"), ("invalid", "invalid:duplicate_sid"),
    ]
    assert (rep.valid, rep.disabled, rep.invalid) == (1, 1, 2)


def test_missing_config_file_warns_and_continues(tmp_path, caplog):
    b = _write(tmp_path, "b.rules", "sid:2\n")
    missing = str(tmp_path / "nope.rules")
    with caplog.at_level(logging.WARNING):
        rules, rep, recs = load_rules(
            _cfg([{"path": missing, "enabled": True}, {"path": b, "enabled": True}]), FakeParser())
    assert [r.sid for r in rules] == [2]
    assert rep.files_failed == 1
    assert any("nope.rules" in m for m in caplog.messages)


def test_directory_instead_of_file_counts_as_failed(tmp_path):
    rules, rep, _ = load_rules(_cfg([{"path": str(tmp_path), "enabled": True}]), FakeParser())
    assert rules == [] and rep.files_failed == 1


def test_file_failing_midway_keeps_earlier_rules(tmp_path, monkeypatch):
    a = _write(tmp_path, "a.rules", "x\n")
    b = _write(tmp_path, "b.rules", "sid:3\n")
    real = loader.iter_rule_lines

    def flaky(path, report=None):
        if str(path) == a:
            yield 1, "sid:1"
            raise OSError("disk error")
        yield from real(path, report)

    monkeypatch.setattr(loader, "iter_rule_lines", flaky)
    rules, rep, _ = load_rules(_cfg([{"path": a, "enabled": True}, {"path": b, "enabled": True}]), FakeParser())
    assert [r.sid for r in rules] == [1, 3]
    assert rep.files_failed == 1


def test_parse_fn_exception_becomes_internal_error(tmp_path, caplog):
    a = _write(tmp_path, "a.rules", "boom\nsid:1\njunk\nsid:2\n")
    with caplog.at_level(logging.WARNING):
        rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}]), FakeParser())
    assert [r.sid for r in rules] == [1, 2]
    assert [(r.status, r.reason) for r in recs] == [
        ("invalid", "invalid:internal_error"), ("valid", None),
        ("invalid", "invalid:internal_error"), ("valid", None),
    ]
    assert (rep.invalid, rep.valid) == (2, 2)


def test_extra_paths_loaded_after_config_files(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\n")
    x = _write(tmp_path, "x.rules", "sid:2\n")
    rules, rep, _ = load_rules(_cfg([{"path": a, "enabled": True}]), FakeParser(), extra_paths=[x])
    assert [r.sid for r in rules] == [1, 2]


def test_missing_extra_path_raises_before_loading(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\n")
    parser = FakeParser()
    with pytest.raises(FileNotFoundError):
        load_rules(_cfg([{"path": a, "enabled": True}]), parser, extra_paths=[tmp_path / "nope.rules"])
    assert parser.calls == []


def test_same_file_listed_twice_loaded_once(tmp_path):
    a = _write(tmp_path, "a.rules", "sid:1\n")
    parser = FakeParser()
    rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}]), parser, extra_paths=[a])
    assert len(rules) == 1 and rep.invalid == 0 and len(parser.calls) == 1


def test_no_files_gives_empty_result():
    rules, rep, recs = load_rules(_cfg([]), FakeParser())
    assert rules == [] and recs == [] and rep.to_dict() == dict.fromkeys(rep.to_dict(), 0)


def test_default_config_missing_default_file_is_not_fatal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rules, rep, _ = load_rules(copy.deepcopy(DEFAULT_CONFIG), FakeParser())
    assert rules == [] and rep.files_failed == 1


def test_extra_path_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(_cfg([]), FakeParser(), extra_paths=[tmp_path])


def test_extra_paths_single_string_is_one_path(tmp_path):
    x = _write(tmp_path, "x.rules", "sid:2\n")
    rules, _, _ = load_rules(_cfg([]), FakeParser(), extra_paths=x)
    assert [r.sid for r in rules] == [2]


def test_invalid_sid_does_not_block_later_valid_rule(tmp_path):
    a = _write(tmp_path, "a.rules", "bad:7\nsid:7\n")
    rules, rep, _ = load_rules(_cfg([{"path": a, "enabled": True}]), FakeParser())
    assert [r.sid for r in rules] == [7] and (rep.invalid, rep.valid) == (1, 1)


def test_rejected_rule_sid_does_not_make_later_valid_rule_a_duplicate(tmp_path):
    a = _write(tmp_path, "a.rules", "bad:1\nunsup\nsid:1\nsid:9\n")
    rules, rep, recs = load_rules(_cfg([{"path": a, "enabled": True}]), FakeParser())
    assert [r.sid for r in rules] == [1, 9]
    assert [r.status for r in recs] == ["invalid", "unsupported", "valid", "valid"]
