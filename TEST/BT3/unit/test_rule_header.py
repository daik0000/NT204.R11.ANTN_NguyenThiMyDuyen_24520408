import pytest

from src.models.rule import IpSpec, PortSpec
from src.models.rule_report import is_valid_reason
from src.rules.parser import (
    UNSUPPORTED_ACTIONS, UNSUPPORTED_PROTOCOLS, RuleSyntaxError, parse_action, parse_direction,
    parse_header, parse_protocol,
)


def _reason(fn, *args):
    with pytest.raises(RuleSyntaxError) as exc:
        fn(*args)
    assert is_valid_reason(exc.value.reason)
    return exc.value.reason


def test_action_alert():
    assert parse_action("alert") == "alert"


@pytest.mark.parametrize("word", ["drop", "reject", "pass", "log", "sdrop", "activate", "dynamic"])
def test_action_unsupported(word):
    assert _reason(parse_action, word) == f"unsupported:action:{word}"


@pytest.mark.parametrize("word", ["Alert", "ALERT", "alerts", "", "foo", "tcp"])
def test_action_bad(word):
    assert _reason(parse_action, word) == "invalid:bad_header"


@pytest.mark.parametrize("word", ["tcp", "udp", "ip"])
def test_protocol_ok(word):
    assert parse_protocol(word) == word


@pytest.mark.parametrize("word", ["icmp", "http", "dns", "smtp", "ftp"])
def test_protocol_unsupported(word):
    assert _reason(parse_protocol, word) == f"unsupported:protocol:{word}"


@pytest.mark.parametrize("word", ["TCP", "Udp", "tcpp", "", "foo", "alert"])
def test_protocol_bad(word):
    assert _reason(parse_protocol, word) == "invalid:bad_header"


@pytest.mark.parametrize("op", ["->", "<>"])
def test_direction_ok(op):
    assert parse_direction(op) == op


@pytest.mark.parametrize("op", ["<-", "=>", "-", "<->", "", "any", "- >"])
def test_direction_bad(op):
    assert _reason(parse_direction, op) == "invalid:bad_direction"


def test_unsupported_sets_do_not_overlap_supported():
    assert not set(UNSUPPORTED_ACTIONS) & {"alert"}
    assert not set(UNSUPPORTED_PROTOCOLS) & {"tcp", "udp", "ip"}


def _hdr(**over):
    base = dict(action="alert", proto="tcp", src_ip="any", src_port="any", dir="->",
                dst_ip="192.168.1.0/24", dst_port="80")
    base.update(over)
    return list(base.values())


def test_parse_header_valid():
    h = parse_header(_hdr())
    assert h.action == "alert" and h.protocol == "tcp" and h.direction == "->"
    assert h.src_ip.any and h.src_port.is_any
    assert h.dst_ip == IpSpec(False, 3232235776, 0xFFFFFF00) and h.dst_port == PortSpec(80, 80)


def test_parse_header_wrong_token_count():
    assert _reason(parse_header, ["alert", "tcp"]) == "invalid:bad_header"


@pytest.mark.parametrize("over, reason", [
    (dict(action="foo"), "invalid:bad_header"),
    (dict(proto="foo"), "invalid:bad_header"),
    (dict(src_ip="300.1.1.1"), "invalid:bad_ip"),
    (dict(dst_ip="10.0.0"), "invalid:bad_ip"),
    (dict(src_port="99999"), "invalid:bad_port"),
    (dict(dst_port="abc"), "invalid:bad_port"),
    (dict(dir="<-"), "invalid:bad_direction"),
    (dict(action="drop"), "unsupported:action:drop"),
    (dict(proto="icmp"), "unsupported:protocol:icmp"),
    (dict(src_ip="$HOME_NET"), "unsupported:ip_syntax"),
    (dict(dst_port="[80,443]"), "unsupported:port_syntax"),
])
def test_parse_header_each_field(over, reason):
    assert _reason(parse_header, _hdr(**over)) == reason


def test_invalid_wins_over_unsupported_regardless_of_order():
    assert _reason(parse_header, _hdr(action="drop", dst_port="99999")) == "invalid:bad_port"
    assert _reason(parse_header, _hdr(proto="icmp", dir="<-")) == "invalid:bad_direction"
    assert _reason(parse_header, _hdr(src_ip="$X", action="foo")) == "invalid:bad_header"


def test_first_error_of_same_kind_wins():
    assert _reason(parse_header, _hdr(src_ip="300.1.1.1", dst_port="abc")) == "invalid:bad_ip"
    assert _reason(parse_header, _hdr(action="drop", proto="icmp")) == "unsupported:action:drop"
