import copy
import functools

import pytest

from src.models.rule import ContentSpec, DsizeSpec, FlagsSpec, FlowSpec, IpSpec, PortSpec
from src.models.rule_report import REASON_CODES, REASON_PREFIXES, ParseResult
from src.rules import validator
from src.rules.validator import parse_rule
from src.utils.config import DEFAULT_CONFIG

H = "alert tcp any any -> any 80"
OK = 'msg:"x"; sid:1;'


def _parse(text, **kw):
    return parse_rule(text, "t.rules", 7, kw.get("cfg"))


def _is(text, status, reason, sid=None):
    r = _parse(text)
    assert (r.status, r.reason) == (status, reason), r
    assert r.rule is None
    assert r.sid == sid
    return r


def _invalid(text, reason, sid=None):
    return _is(text, "invalid", reason, sid)


def _unsup(text, reason, sid=None):
    return _is(text, "unsupported", reason, sid)


# --- a complete valid rule, field by field ---------------------------------------------------------

FULL = (
    'alert tcp 10.0.0.0/8 1024: -> 192.168.1.5 80 (msg:"WEB traversal; test"; '
    'content:"GET"; nocase; offset:0; depth:3; content:"../"; distance:1; within:10; '
    'flow:to_server,established; flags:A+; dsize:>10; sid:1000001; rev:2; '
    'classtype:web-application-attack; priority:1; reference:url,example.com; gid:1;)'
)


def test_full_rule_fields():
    r = parse_rule(FULL, "a.rules", 12, DEFAULT_CONFIG)
    assert r.status == "valid" and r.reason is None and r.sid == 1000001
    rule = r.rule
    assert (rule.action, rule.protocol, rule.direction) == ("alert", "tcp", "->")
    assert rule.src_ip == IpSpec(False, 167772160, 0xFF000000)
    assert rule.src_port == PortSpec(1024, 65535)
    assert rule.dst_ip == IpSpec(False, 3232235781, 0xFFFFFFFF)
    assert rule.dst_port == PortSpec(80, 80)
    assert (rule.msg, rule.sid, rule.rev, rule.classtype, rule.priority) == (
        "WEB traversal; test", 1000001, 2, "web-application-attack", 1)
    assert rule.contents == (
        ContentSpec("GET", b"GET", nocase=True, offset=0, depth=3),
        ContentSpec("../", b"../", distance=1, within=10),
    )
    assert rule.flow == FlowSpec("to_server", "established")
    assert rule.flags == FlagsSpec("all", frozenset("A"))
    assert rule.dsize == DsizeSpec("gt", 10)
    assert rule.passive_options == (("reference", "url,example.com"), ("gid", "1"))
    assert (rule.source_file, rule.line_no, rule.raw) == ("a.rules", 12, FULL)


def test_minimal_rule_defaults_and_cfg_priority():
    r = parse_rule(f"{H} ({OK})", "a", 1, DEFAULT_CONFIG).rule
    assert (r.rev, r.classtype, r.priority) == (1, None, 3)
    assert (r.contents, r.flow, r.flags, r.dsize, r.passive_options) == ((), None, None, None, ())
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["engine"]["default_priority"] = 7
    assert parse_rule(f"{H} ({OK})", "a", 1, cfg).rule.priority == 7
    assert parse_rule(f"{H} ({OK} priority:2;)", "a", 1, cfg).rule.priority == 2


def test_cfg_missing_uses_builtin_default():
    assert parse_rule(f"{H} ({OK})").rule.priority == 3
    assert parse_rule(f"{H} ({OK})", cfg={}).rule.priority == 3


def test_leading_blanks_and_trailing_blanks():
    r = parse_rule(f"   \t{H} ({OK})   ", "a", 1)
    assert r.status == "valid" and r.rule.raw.startswith("   ")


def test_works_as_parse_fn_with_partial():
    fn = functools.partial(parse_rule, cfg=DEFAULT_CONFIG)
    r = fn(f"{H} ({OK})", "a.rules", 3)
    assert r.status == "valid" and r.rule.source_file == "a.rules" and r.rule.line_no == 3


def test_stateless():
    a = parse_rule(f"{H} ({OK})", "a", 1)
    b = parse_rule(f"{H} ({OK})", "b", 2)
    assert a.status == b.status == "valid" and a.rule.source_file == "a" and b.rule.source_file == "b"


def test_never_returns_duplicate_or_disabled():
    for r in (_parse(f"{H} ({OK})"), _parse(f"{H} ({OK})")):
        assert r.reason is None


# --- every reason code ---------------------------------------------------------------------------------

def test_malformed_rule():
    _invalid("alert tcp any any -> any 80", "invalid:malformed_rule")
    _invalid(f"{H} (sid:1;", "invalid:malformed_rule")
    _invalid(f"{H} (sid:1;) x", "invalid:malformed_rule")
    _invalid("", "invalid:malformed_rule")


def test_bad_header():
    _invalid(f"alert tcp any any -> any ({OK})", "invalid:bad_header")      # 6 tokens: no sid is read
    _invalid(f"foo tcp any any -> any 80 ({OK})", "invalid:bad_header", sid=1)
    _invalid(f"alert foo any any -> any 80 ({OK})", "invalid:bad_header", sid=1)


def test_bad_ip():
    _invalid(f"alert tcp 300.1.1.1 any -> any 80 ({OK})", "invalid:bad_ip", sid=1)
    _invalid(f"alert tcp any any -> 10.0.0 80 ({OK})", "invalid:bad_ip", sid=1)


def test_bad_port():
    _invalid(f"alert tcp any 99999 -> any 80 ({OK})", "invalid:bad_port", sid=1)
    _invalid(f"alert tcp any any -> any 90:80 ({OK})", "invalid:bad_port", sid=1)


def test_bad_direction():
    _invalid(f"alert tcp any any <- any 80 ({OK})", "invalid:bad_direction", sid=1)


def test_missing_sid():
    _invalid(f'{H} (msg:"x";)', "invalid:missing_sid")
    _invalid(f"{H} ()", "invalid:missing_sid")


@pytest.mark.parametrize("sid", ["0", "-1", "abc", "", "1.5"])
def test_bad_sid(sid):
    _invalid(f'{H} (msg:"x"; sid:{sid};)', "invalid:bad_sid")


def test_missing_msg():
    _invalid(f"{H} (sid:1;)", "invalid:missing_msg", sid=1)
    _invalid(f"{H} (msg:hello; sid:1;)", "invalid:missing_msg", sid=1)


def test_bad_option_value():
    _invalid(f'{H} ({OK} rev:0;)', "invalid:bad_option_value:rev", sid=1)
    _invalid(f'{H} ({OK} priority:x;)', "invalid:bad_option_value:priority", sid=1)
    _invalid(f'{H} ({OK} classtype:a b;)', "invalid:bad_option_value:classtype", sid=1)
    _invalid(f'{H} ({OK} content:"|4|";)', "invalid:bad_option_value:content", sid=1)
    _invalid(f'{H} ({OK} content:"a"; offset:x;)', "invalid:bad_option_value:offset", sid=1)
    _invalid(f'{H} ({OK} content:"a"; within:0;)', "invalid:bad_option_value:within", sid=1)
    _invalid(f'{H} ({OK} flow;)', "invalid:bad_option_value:flow", sid=1)
    _invalid(f'{H} ({OK} flags:XYZ;)', "invalid:bad_option_value:flags", sid=1)
    _invalid(f'{H} ({OK} dsize:abc;)', "invalid:bad_option_value:dsize", sid=1)


def test_duplicate_option():
    _invalid(f'{H} ({OK} msg:"y";)', "invalid:duplicate_option:msg", sid=1)
    _invalid(f'{H} (msg:"x"; sid:1; sid:2;)', "invalid:duplicate_option:sid")
    _invalid(f'{H} ({OK} content:"a"; nocase; nocase;)', "invalid:duplicate_option:nocase", sid=1)
    _invalid(f'{H} ({OK} flow:to_server; flow:to_client;)', "invalid:duplicate_option:flow", sid=1)
    _invalid(f'{H} ({OK} flags:S; flags:A;)', "invalid:duplicate_option:flags", sid=1)
    _invalid(f'{H} ({OK} dsize:1; dsize:2;)', "invalid:duplicate_option:dsize", sid=1)


def test_modifier_without_content():
    _invalid(f"{H} ({OK} nocase;)", "invalid:modifier_without_content", sid=1)
    _invalid(f"{H} ({OK} offset:1; content:\"a\";)", "invalid:modifier_without_content", sid=1)


def test_depth_lt_pattern():
    _invalid(f'{H} ({OK} content:"abcd"; depth:3;)', "invalid:depth_lt_pattern", sid=1)
    assert _parse(f'{H} ({OK} content:"abcd"; depth:4;)').status == "valid"


def test_within_lt_pattern():
    _invalid(f'{H} ({OK} content:"a"; content:"abcd"; within:3;)', "invalid:within_lt_pattern", sid=1)
    assert _parse(f'{H} ({OK} content:"a"; content:"abcd"; within:4;)').status == "valid"


def test_depth_and_within_use_byte_length_of_decoded_pattern():
    assert _parse(f'{H} ({OK} content:"|41 42 43|"; depth:3;)').status == "valid"
    _invalid(f'{H} ({OK} content:"|41 42 43|"; depth:2;)', "invalid:depth_lt_pattern", sid=1)
    _invalid(f'{H} ({OK} content:"é"; depth:1;)', "invalid:depth_lt_pattern", sid=1)   # 2 UTF-8 bytes


@pytest.mark.parametrize("mods", ["offset:0; distance:1", "depth:9; within:9", "offset:0; within:9", "depth:9; distance:1"])
def test_mixed_absolute_relative(mods):
    _invalid(f'{H} ({OK} content:"a"; {mods};)', "invalid:mixed_absolute_relative", sid=1)


def test_absolute_and_relative_on_different_contents_is_fine():
    r = _parse(f'{H} ({OK} content:"a"; offset:0; content:"b"; distance:1; within:5;)')
    assert r.status == "valid"


def test_flags_requires_tcp():
    _invalid(f"alert udp any any -> any 53 ({OK} flags:S;)", "invalid:flags_requires_tcp", sid=1)
    assert _parse(f"alert ip any any -> any any ({OK} flags:S;)").status == "valid"
    assert _parse(f"alert tcp any any -> any any ({OK} flags:S;)").status == "valid"


def test_conflicting_flow():
    _invalid(f"{H} ({OK} flow:to_server,to_client;)", "invalid:conflicting_flow", sid=1)
    _invalid(f"{H} ({OK} flow:established,not_established;)", "invalid:conflicting_flow", sid=1)


def test_internal_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(validator, "parse_identification", boom)
    r = _parse(f"{H} ({OK})")
    assert (r.status, r.reason, r.rule) == ("invalid", "invalid:internal_error", None)


def test_internal_error_from_any_stage_is_swallowed(monkeypatch):
    monkeypatch.setattr(validator, "parse_contents_full", lambda options: ((object(),), None))
    r = _parse(f"{H} ({OK})")
    assert (r.status, r.reason) == ("invalid", "invalid:internal_error")


def test_unsupported_action():
    _unsup(f"drop tcp any any -> any 80 ({OK})", "unsupported:action:drop", sid=1)
    _unsup(f"reject tcp any any -> any 80 ({OK})", "unsupported:action:reject", sid=1)


def test_unsupported_protocol():
    _unsup(f"alert icmp any any -> any any ({OK})", "unsupported:protocol:icmp", sid=1)
    _unsup(f"alert http any any -> any any ({OK})", "unsupported:protocol:http", sid=1)


def test_unsupported_ip_and_port_syntax():
    _unsup(f"alert tcp $HOME_NET any -> any 80 ({OK})", "unsupported:ip_syntax", sid=1)
    _unsup(f"alert tcp any any -> any [80,443] ({OK})", "unsupported:port_syntax", sid=1)


@pytest.mark.parametrize("kw", ["pcre", "byte_test", "flowbits", "threshold", "http_uri", "fast_pattern", "ttl"])
def test_unsupported_keyword(kw):
    _unsup(f"{H} ({OK} {kw}:1;)", f"unsupported:keyword:{kw}", sid=1)


def test_unsupported_flow_option():
    _unsup(f"{H} ({OK} flow:established,stateless;)", "unsupported:flow_option:stateless", sid=1)


def test_unsupported_flags_mask():
    _unsup(f"{H} ({OK} flags:SA,12;)", "unsupported:flags_mask", sid=1)


def test_unsupported_content_negation():
    _unsup(f'{H} ({OK} content:!"abc";)', "unsupported:content_negation", sid=1)


def test_every_reason_code_family_is_covered_by_this_file():
    # codes produced by the Loader, not the Parser
    loader_only = {"invalid:duplicate_sid", "disabled:sid"}
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    for code in REASON_CODES:
        if code in loader_only:
            continue
        assert code in source, f"no test case for {code}"
    for prefix in REASON_PREFIXES:
        assert prefix in source, f"no test case for {prefix}<x>"


# --- priority of classification ---------------------------------------------------------------------------

def test_unsupported_header_with_missing_sid_is_invalid():
    _invalid("alert icmp any any -> any any (msg:\"x\";)", "invalid:missing_sid")


def test_invalid_header_stops_before_options():
    _invalid(f'alert tcp any 99999 -> any 80 (msg:"x"; sid:abc;)', "invalid:bad_port")


def test_invalid_header_wins_over_unsupported_header_field():
    _invalid(f"drop tcp any 99999 -> any 80 ({OK})", "invalid:bad_port", sid=1)


@pytest.mark.parametrize("text, reason", [
    (f"alert icmp any any -> any any (msg:\"x\"; sid:abc;)", "invalid:bad_sid"),
    (f"drop tcp any any -> any 80 ({OK} content:\"abcd\"; depth:2;)", "invalid:depth_lt_pattern"),
    (f"drop udp any any -> any 53 ({OK} flags:S;)", "invalid:flags_requires_tcp"),
    (f"alert tcp $HOME_NET any -> any 80 ({OK} dsize:abc;)", "invalid:bad_option_value:dsize"),
    (f"{H} ({OK} flow:stateless; dsize:abc;)", "invalid:bad_option_value:dsize"),
    (f'{H} ({OK} content:!"a"; offset:x;)', "invalid:bad_option_value:offset"),
    (f"{H} ({OK} flags:SA,12; flow:to_server,to_client;)", "invalid:conflicting_flow"),
    (f"{H} ({OK} pcre:1; dsize:abc;)", "invalid:bad_option_value:dsize"),
    (f"{H} ({OK} pcre:1; nocase;)", "invalid:modifier_without_content"),
    (f"{H} ({OK} flags:X,12;)", "invalid:bad_option_value:flags"),
    # a negated content still takes part in the cross-option checks
    (f'{H} ({OK} content:!"a"; content:"abcd"; depth:2;)', "invalid:depth_lt_pattern"),
    (f'{H} ({OK} content:!"abcd"; depth:2;)', "invalid:depth_lt_pattern"),
    (f'{H} ({OK} content:!"a"; content:"b"; offset:0; distance:1;)', "invalid:mixed_absolute_relative"),
    (f'{H} ({OK} content:!"a"; offset:0; within:9;)', "invalid:mixed_absolute_relative"),
    (f'{H} ({OK} content:!"abcd"; content:"x"; within:1; content:"abcd"; within:2;)', "invalid:within_lt_pattern"),
    (f'{H} ({OK} content:!"|4|";)', "invalid:bad_option_value:content"),
    (f'{H} ({OK} content:!"a"; nocase; nocase;)', "invalid:duplicate_option:nocase"),
])
def test_invalid_wins_over_unsupported(text, reason):
    r = _parse(text)
    assert (r.status, r.reason) == ("invalid", reason)


def test_several_unsupported_header_first():
    _unsup(f"drop tcp any any -> any 80 ({OK} pcre:1; flow:stateless;)", "unsupported:action:drop", sid=1)
    _unsup(f"alert icmp any any -> any any ({OK} flags:S,1;)", "unsupported:protocol:icmp", sid=1)


def test_several_unsupported_value_level_before_keyword():
    text = f'{H} ({OK} pcre:1; flags:S,1; flow:stateless; content:!"a";)'
    _unsup(text, "unsupported:content_negation", sid=1)
    _unsup(f"{H} ({OK} pcre:1; flags:S,1; flow:stateless;)", "unsupported:flow_option:stateless", sid=1)
    _unsup(f"{H} ({OK} pcre:1; flags:S,1;)", "unsupported:flags_mask", sid=1)
    _unsup(f"{H} ({OK} ttl:1; pcre:1;)", "unsupported:keyword:ttl", sid=1)


def test_uppercase_protocol_is_not_normalised_so_flags_check_cannot_be_bypassed():
    _invalid(f"alert UDP any any -> any 53 ({OK} flags:S;)", "invalid:bad_header", sid=1)


def test_out_of_range_sid_is_not_reported():
    assert _parse(f'{H} (msg:"x"; sid:99999999999; rev:0;)').sid is None
    assert _parse(f'{H} (msg:"x"; sid:4294967295; rev:0;)').sid == 4294967295


def test_internal_error_is_logged_with_traceback(monkeypatch, caplog):
    monkeypatch.setattr(validator, "parse_identification", lambda *a, **k: 1 / 0)
    _parse(f"{H} ({OK})")
    assert any(rec.exc_info for rec in caplog.records)


def test_sid_reported_for_rejected_rules_only_when_unambiguous():
    assert _parse(f"{H} ({OK} rev:0;)").sid == 1
    assert _parse(f'{H} (msg:"x"; sid:1; sid:2; rev:0;)').sid is None
    assert _parse(f'{H} (msg:"x"; sid:abc; rev:0;)').sid is None
