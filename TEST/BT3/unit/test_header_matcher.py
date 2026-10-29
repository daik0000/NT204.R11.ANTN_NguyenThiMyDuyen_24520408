import pytest

from src.engine.matcher import match_header
from src.models.event import IDSEvent
from src.rules.validator import parse_rule


def rule(text):
    result = parse_rule(text)
    assert result.status == "valid", (text, result)
    return result.rule


def pkt(src, dst, proto="TCP", **kw):
    d = dict(packet_id=1, timestamp=1.0, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"")
    d.update(kw)
    return IDSEvent(**d)


# --- T05: hand-computed ----------------------------------------------------------------------------------

ONE_WAY = rule('alert tcp 10.0.0.5 any -> 192.168.1.20 80 (msg:"x"; sid:1;)')
BOTH_WAYS = rule('alert tcp 10.0.0.5 any <> 192.168.1.20 80 (msg:"x"; sid:2;)')

T05 = [
    (("10.0.0.5", 52133), ("192.168.1.20", 80), True, True),
    (("192.168.1.20", 80), ("10.0.0.5", 52133), False, True),
    (("10.9.9.9", 52133), ("192.168.1.20", 80), False, False),
]


@pytest.mark.parametrize("src, dst, one_way, both_ways", T05)
def test_t05(src, dst, one_way, both_ways):
    assert match_header(ONE_WAY, pkt(src, dst)) is one_way
    assert match_header(BOTH_WAYS, pkt(src, dst)) is both_ways


def test_reversal_swaps_ip_and_port_together():
    # the packet has the rule's SOURCE ip but the rule's DESTINATION port: neither way matches
    mixed = pkt(("10.0.0.5", 80), ("192.168.1.20", 52133))
    assert match_header(BOTH_WAYS, mixed) is False
    # and the other mix: destination ip with the source's port range is irrelevant (src port is any),
    # so use a rule with a fixed source port to prove the pair is compared together
    r = rule('alert tcp 10.0.0.5 1000 <> 192.168.1.20 80 (msg:"x"; sid:3;)')
    assert match_header(r, pkt(("192.168.1.20", 80), ("10.0.0.5", 1000))) is True
    assert match_header(r, pkt(("192.168.1.20", 1000), ("10.0.0.5", 80))) is False     # ports not swapped
    assert match_header(r, pkt(("10.0.0.5", 80), ("192.168.1.20", 1000))) is False


# --- protocol -------------------------------------------------------------------------------------------------

def test_protocol_must_agree():
    assert match_header(rule('alert udp any any -> any any (msg:"x"; sid:1;)'), pkt(("1.1.1.1", 1), ("2.2.2.2", 2), "UDP"))
    assert not match_header(rule('alert udp any any -> any any (msg:"x"; sid:1;)'), pkt(("1.1.1.1", 1), ("2.2.2.2", 2), "TCP"))
    assert not match_header(rule('alert tcp any any -> any any (msg:"x"; sid:1;)'), pkt(("1.1.1.1", 1), ("2.2.2.2", 2), "UDP"))


@pytest.mark.parametrize("proto", ["TCP", "UDP", "tcp", "Udp"])
def test_ip_rule_matches_tcp_and_udp_in_any_letter_case(proto):
    assert match_header(rule('alert ip any any -> any any (msg:"x"; sid:1;)'), pkt(("1.1.1.1", 1), ("2.2.2.2", 2), proto))


@pytest.mark.parametrize("proto", [None, "ICMP", "", 6])
def test_other_transport_protocols_never_match_not_even_ip_rules(proto):
    r = rule('alert ip any any -> any any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("1.1.1.1", 1), ("2.2.2.2", 2), proto)) is False


# --- addresses and ports -----------------------------------------------------------------------------------------------

def test_cidr_and_host_bits():
    r = rule('alert tcp 192.168.1.0/24 any -> 10.0.0.0/8 any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("192.168.1.77", 1), ("10.255.255.255", 2)))
    assert not match_header(r, pkt(("192.168.2.77", 1), ("10.1.1.1", 2)))
    assert not match_header(r, pkt(("192.168.1.77", 1), ("11.0.0.1", 2)))


def test_host_bits_in_the_rule_are_cleared():
    r = rule('alert tcp 10.0.0.5/24 any -> any any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("10.0.0.200", 1), ("1.1.1.1", 2)))


def test_single_address_is_a_32_bit_match():
    r = rule('alert tcp 10.0.0.5 any -> any any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("10.0.0.5", 1), ("1.1.1.1", 2)))
    assert not match_header(r, pkt(("10.0.0.6", 1), ("1.1.1.1", 2)))


def test_any_address_matches_everything():
    r = rule('alert tcp any any -> any any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("0.0.0.0", 0), ("255.255.255.255", 65535)))


@pytest.mark.parametrize("spec, port, expected", [
    ("80", 80, True), ("80", 81, False),
    ("1:1024", 1, True), ("1:1024", 1024, True), ("1:1024", 0, False), ("1:1024", 1025, False),
    (":1023", 0, True), (":1023", 1024, False),
    ("5000:", 5000, True), ("5000:", 65535, True), ("5000:", 4999, False),
    ("any", 12345, True),
])
def test_dst_port_forms(spec, port, expected):
    r = rule(f'alert tcp any any -> any {spec} (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("1.1.1.1", 40000), ("2.2.2.2", port))) is expected


def test_source_port_is_checked_for_one_way_rules():
    r = rule('alert tcp any 1000:2000 -> any any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("1.1.1.1", 1500), ("2.2.2.2", 80)))
    assert not match_header(r, pkt(("1.1.1.1", 3000), ("2.2.2.2", 80)))


# --- invalid events: False, never an exception -------------------------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    dict(src_ip=None), dict(dst_ip=None), dict(src_ip="300.1.1.1"), dict(dst_ip="10.0.0"),
    dict(src_ip="::1"), dict(src_ip=""), dict(src_ip=167772165), dict(src_ip="10.0.0.5/24"),
    dict(src_ip=" 10.0.0.5"), dict(dst_ip=b"1.1.1.1"),
    dict(src_port=None), dict(dst_port=None), dict(src_port=-1), dict(dst_port=65536),
    dict(src_port="80"), dict(dst_port=80.0), dict(dst_port=True),
])
def test_invalid_event_fields_do_not_match_and_do_not_raise(kw):
    r = rule('alert tcp any any <> any any (msg:"x"; sid:1;)')
    event = pkt(("10.0.0.5", 1000), ("192.168.1.20", 80), **kw)
    assert match_header(r, event) is False


def test_event_without_the_attributes_at_all():
    class Bare:
        pass
    assert match_header(rule('alert ip any any -> any any (msg:"x"; sid:1;)'), Bare()) is False


def test_corrupt_ip_does_not_match_even_an_any_any_rule():
    r = rule('alert tcp any any -> any any (msg:"x"; sid:1;)')
    assert match_header(r, pkt(("999.1.1.1", 1), ("2.2.2.2", 2))) is False
    assert match_header(r, pkt(("1.1.1.1", 1), ("2.2.2.2", 2))) is True
