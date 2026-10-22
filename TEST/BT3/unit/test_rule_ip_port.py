import pytest

from src.models.rule import IpSpec, PortSpec
from src.models.rule_report import is_valid_reason
from src.rules.parser import RuleSyntaxError, parse_ip, parse_port


@pytest.mark.parametrize("token, network, mask", [
    ("10.0.0.5", 167772165, 0xFFFFFFFF),
    ("192.168.1.0/24", 3232235776, 0xFFFFFF00),
    ("10.0.0.0/8", 167772160, 0xFF000000),
    ("10.0.0.5/24", 167772160, 0xFFFFFF00),
    ("10.0.0.5/32", 167772165, 0xFFFFFFFF),
    ("0.0.0.0/0", 0, 0),
    ("255.255.255.255", 0xFFFFFFFF, 0xFFFFFFFF),
])
def test_parse_ip_valid(token, network, mask):
    assert parse_ip(token) == IpSpec(any=False, network=network, mask=mask)


def test_parse_ip_any():
    spec = parse_ip("any")
    assert spec.any is True


def test_cidr_matching_semantics():
    spec = parse_ip("192.168.1.0/24")
    assert (0xC0A80163 & spec.mask) == spec.network          # 192.168.1.99
    assert (0xC0A80263 & spec.mask) != spec.network          # 192.168.2.99


def _reason(fn, token):
    with pytest.raises(RuleSyntaxError) as exc:
        fn(token)
    assert is_valid_reason(exc.value.reason)
    return exc.value.reason


@pytest.mark.parametrize("token", ["$HOME_NET", "!10.0.0.1", "![10.0.0.0/8]", "[10.0.0.1,10.0.0.2]", "[any]"])
def test_parse_ip_unsupported(token):
    assert _reason(parse_ip, token) == "unsupported:ip_syntax"


@pytest.mark.parametrize("token", [
    "300.1.1.1", "10.0.0", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/", "1.2.3.4/abc",
    "1.2.3.4/255.255.255.0", "1.2.3.4/٣", "::1", "2001:db8::/32", "fe80::1/64",
    "", "ANY", "host", "10.0.0.1,10.0.0.2", "01.2.3.4", " 10.0.0.1", "1.2.3.4 ",
])
def test_parse_ip_bad(token):
    assert _reason(parse_ip, token) == "invalid:bad_ip"


@pytest.mark.parametrize("token, lo, hi", [
    ("any", 0, 65535),
    ("80", 80, 80),
    ("0", 0, 0),
    ("65535", 65535, 65535),
    ("1:1024", 1, 1024),
    (":1023", 0, 1023),
    ("5000:", 5000, 65535),
    ("80:80", 80, 80),
    ("0:65535", 0, 65535),
    ("0080", 80, 80),
])
def test_parse_port_valid(token, lo, hi):
    assert parse_port(token) == PortSpec(lo, hi)


def test_parse_port_any_is_any():
    assert parse_port("any").is_any and parse_port("0:65535").is_any


@pytest.mark.parametrize("token", ["$HTTP_PORTS", "!80", "[80,443]", "!1:1024", "[80:90]"])
def test_parse_port_unsupported(token):
    assert _reason(parse_port, token) == "unsupported:port_syntax"


@pytest.mark.parametrize("token", [
    "65536", "99999999999", "-1", "+80", "abc", "80a", "", ":", "1:2:3", "1024:80", "70000:",
    ":70000", "٣", "٣٣", " 80", "80 ", "8 0", "1.5", "ANY", "80,443", "9" * 5000,
])
def test_parse_port_bad(token):
    assert _reason(parse_port, token) == "invalid:bad_port"
