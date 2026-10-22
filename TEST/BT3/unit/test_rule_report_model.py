import dataclasses
import json

import pytest

from src.models.rule import IpSpec, PortSpec, Rule
from src.models.rule_report import (
    RECORD_STATUSES, REASON_CODES, REASON_PREFIXES, RULE_STATUSES, LoadReport, ParseResult, RuleRecord, is_valid_reason,
)

RULE = Rule(action="alert", protocol="tcp", src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535),
            direction="->", dst_ip=IpSpec(any=True), dst_port=PortSpec(0, 65535), msg="m", sid=1)

SPEC_CODES = """
invalid:malformed_rule invalid:bad_header invalid:bad_ip invalid:bad_port invalid:bad_direction
invalid:missing_sid invalid:bad_sid invalid:duplicate_sid invalid:missing_msg
invalid:modifier_without_content invalid:depth_lt_pattern invalid:within_lt_pattern
invalid:mixed_absolute_relative invalid:flags_requires_tcp invalid:conflicting_flow
invalid:internal_error unsupported:ip_syntax unsupported:port_syntax unsupported:flags_mask
unsupported:content_negation disabled:sid
""".split()


def test_fixed_codes_match_spec():
    assert sorted(REASON_CODES) == sorted(SPEC_CODES)


def test_prefixes():
    assert set(REASON_PREFIXES) == {
        "invalid:bad_option_value:", "invalid:duplicate_option:", "unsupported:action:",
        "unsupported:protocol:", "unsupported:keyword:", "unsupported:flow_option:",
    }


@pytest.mark.parametrize("reason", SPEC_CODES + [
    "invalid:bad_option_value:depth", "invalid:duplicate_option:sid", "unsupported:action:drop",
    "unsupported:protocol:icmp", "unsupported:keyword:pcre", "unsupported:flow_option:stateless",
])
def test_known_reasons(reason):
    assert is_valid_reason(reason)


@pytest.mark.parametrize("reason", [
    "invalid:nope", "unsupported:keyword:", "invalid:bad_option_value:", "missing_sid", "",
    "unsupported:malformed_rule",
])
def test_unknown_reasons(reason):
    assert not is_valid_reason(reason)


def test_parse_result_valid():
    r = ParseResult("valid", rule=RULE, sid=1)
    assert r.reason is None and r.rule is RULE


def test_parse_result_rejected():
    r = ParseResult("invalid", reason="invalid:missing_sid")
    assert r.rule is None and r.sid is None
    assert ParseResult("unsupported", reason="unsupported:keyword:pcre", sid=7).sid == 7


@pytest.mark.parametrize("kwargs", [
    dict(status="valid"),                                                  # no rule
    dict(status="valid", rule=RULE, reason="invalid:bad_ip"),              # reason on valid
    dict(status="invalid", rule=RULE, reason="invalid:bad_ip"),            # rule on invalid
    dict(status="invalid"),                                                # no reason
    dict(status="invalid", reason="unsupported:ip_syntax"),                # status/reason mismatch
    dict(status="invalid", reason="invalid:made_up"),
    dict(status="maybe", reason="invalid:bad_ip"),
])
def test_parse_result_rejects_inconsistent(kwargs):
    with pytest.raises(ValueError):
        ParseResult(**kwargs)


def test_parse_result_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        ParseResult("invalid", reason="invalid:bad_ip").status = "valid"


def test_rule_record_to_dict_is_json_serialisable():
    rec = RuleRecord("a.rules", 3, "invalid", "invalid:missing_sid", None, "alert tcp ...")
    d = rec.to_dict()
    assert list(d) == ["file", "line", "status", "reason", "sid", "text"]
    assert json.loads(json.dumps(d)) == d


def test_rule_record_validates():
    assert RuleRecord("a", 1, "valid", None, 5, "x").reason is None
    with pytest.raises(ValueError):
        RuleRecord("a", 1, "unsupported", "invalid:bad_ip", None, "x")


def test_rule_record_disabled():
    rec = RuleRecord("a", 2, "disabled", "disabled:sid", 1000001, "alert ...")
    assert rec.to_dict()["status"] == "disabled"
    assert "disabled" in RECORD_STATUSES and "disabled" not in RULE_STATUSES


@pytest.mark.parametrize("reason, sid", [(None, 5), ("invalid:bad_ip", 5), ("disabled:sid", None)])
def test_rule_record_disabled_inconsistent(reason, sid):
    with pytest.raises(ValueError):
        RuleRecord("a", 2, "disabled", reason, sid, "x")


def test_parse_result_never_disabled():
    with pytest.raises(ValueError):
        ParseResult("disabled", reason="disabled:sid", sid=1)


def test_is_valid_reason_non_string():
    assert not is_valid_reason(None)
    assert not is_valid_reason(5)


def test_load_report_defaults_and_dict():
    rep = LoadReport()
    assert rep.to_dict() == {
        "total_lines": 0, "blank": 0, "comment": 0, "rule_lines": 0, "valid": 0,
        "invalid": 0, "unsupported": 0, "disabled": 0, "files_failed": 0,
    }
    rep.valid += 1
    assert rep.to_dict()["valid"] == 1
