import pytest

from src.rules.indexer import RuleIndexer
from src.rules.repository import RuleRepository
from src.rules.validator import parse_rule

# T06: seven rules, hand-computed candidate lists (prefilter on protocol + destination port only)
T06_RULES = [
    'alert tcp any any -> any 80 (msg:"1"; sid:1;)',
    'alert tcp any any -> any 1:1024 (msg:"2"; sid:2;)',
    'alert tcp any any -> any any (msg:"3"; sid:3;)',
    'alert udp any any -> any 53 (msg:"4"; sid:4;)',
    'alert ip any any -> any any (msg:"5"; sid:5;)',
    'alert udp any any -> any 5000:6000 (msg:"6"; sid:6;)',
    'alert tcp any 443 <> any 8443 (msg:"7"; sid:7;)',
]

T06_EXPECTED = [
    ("tcp", 80, [1, 2, 3, 5]),
    ("tcp", 443, [2, 3, 5, 7]),
    ("tcp", 8443, [3, 5, 7]),
    ("tcp", 2000, [3, 5]),
    ("udp", 53, [4, 5]),
    ("udp", 5500, [5, 6]),
    ("udp", 80, [5]),
]


def _index(lines):
    repo = RuleRepository()
    for line in lines:
        result = parse_rule(line)
        assert result.status == "valid", (line, result)
        repo.add(result.rule)
    repo.freeze()
    return RuleIndexer(repo)


def _sids(idx, protocol, port):
    return [r.sid for r in idx.candidates(protocol, port)]


@pytest.fixture(scope="module")
def t06():
    return _index(T06_RULES)


@pytest.mark.parametrize("protocol, port, expected", T06_EXPECTED)
def test_t06_candidates(t06, protocol, port, expected):
    assert _sids(t06, protocol, port) == expected


def test_t06_reverse_direction_of_bidirectional_rule_is_not_missed(t06):
    # 443 is the rule's SOURCE port; a packet going back to the client port 443 must still see it
    assert 7 in _sids(t06, "tcp", 443)
    assert 7 in _sids(t06, "tcp", 8443)


def test_unidirectional_rule_is_filed_by_destination_port_only():
    idx = _index(['alert tcp any 443 -> any 8443 (msg:"a"; sid:1;)'])
    assert _sids(idx, "tcp", 8443) == [1]
    assert _sids(idx, "tcp", 443) == []


def test_bidirectional_rule_with_ranges_and_any():
    idx = _index([
        'alert tcp any 1000:2000 <> any 3000:4000 (msg:"a"; sid:1;)',
        'alert udp any any <> any 53 (msg:"b"; sid:2;)',
    ])
    assert _sids(idx, "tcp", 1500) == [1] and _sids(idx, "tcp", 3500) == [1]
    assert _sids(idx, "tcp", 2500) == []
    assert _sids(idx, "udp", 9999) == [2]            # source side is 'any'


def test_rule_filed_twice_is_returned_once():
    idx = _index([
        'alert tcp any any <> any any (msg:"a"; sid:1;)',
        'alert tcp any 80 <> any 80 (msg:"b"; sid:2;)',
        'alert tcp any 1:100 <> any 50:150 (msg:"c"; sid:3;)',
    ])
    assert _sids(idx, "tcp", 80) == [1, 2, 3]
    assert _sids(idx, "tcp", 75) == [1, 3]


def test_result_is_in_repository_order_across_buckets():
    idx = _index([
        'alert ip any any -> any any (msg:"a"; sid:30;)',
        'alert tcp any any -> any 80 (msg:"b"; sid:10;)',
        'alert tcp any any -> any any (msg:"c"; sid:20;)',
        'alert ip any any -> any 80 (msg:"d"; sid:5;)',
    ])
    assert _sids(idx, "tcp", 80) == [30, 10, 20, 5]
    assert _sids(idx, "udp", 80) == [30, 5]


def test_range_boundaries_are_inclusive():
    idx = _index(['alert tcp any any -> any 100:200 (msg:"a"; sid:1;)'])
    assert [_sids(idx, "tcp", p) for p in (99, 100, 150, 200, 201)] == [[], [1], [1], [1], []]


def test_port_zero_and_65535():
    idx = _index([
        'alert tcp any any -> any 0 (msg:"a"; sid:1;)',
        'alert tcp any any -> any 65535 (msg:"b"; sid:2;)',
        'alert tcp any any -> any 60000: (msg:"c"; sid:3;)',
    ])
    assert _sids(idx, "tcp", 0) == [1]
    assert _sids(idx, "tcp", 65535) == [2, 3]


def test_empty_repository():
    repo = RuleRepository()
    repo.freeze()
    idx = RuleIndexer(repo)
    assert len(idx) == 0 and idx.candidates("tcp", 80) == []


@pytest.mark.parametrize("protocol", ["icmp", "arp", "", "http", None, 6, "tcpp"])
def test_unknown_protocol_gives_empty_list(t06, protocol):
    assert t06.candidates(protocol, 80) == []


@pytest.mark.parametrize("port", [-1, 65536, 70000, None, "80", 80.0, True])
def test_bad_port_gives_empty_list(t06, port):
    assert t06.candidates("tcp", port) == []


def test_protocol_letter_case_is_ignored(t06):
    assert _sids(t06, "TCP", 80) == [1, 2, 3, 5]
    assert _sids(t06, "Udp", 53) == [4, 5]


def test_ip_lookup_uses_only_the_ip_bucket(t06):
    assert _sids(t06, "ip", 80) == [5]


def test_event_without_a_port_has_no_candidates(t06):
    # ICMP / ARP / missing transport: ip-rules do not apply to them in this implementation
    assert t06.candidates("icmp", None) == [] and t06.candidates("tcp", None) == []


def test_rule_with_unknown_protocol_cannot_even_be_built():
    from src.models.rule import IpSpec, PortSpec, Rule
    with pytest.raises(ValueError):
        Rule(action="alert", protocol="icmp", src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535),
             direction="->", dst_ip=IpSpec(any=True), dst_port=PortSpec(0, 65535), msg="m", sid=1)


def test_candidates_returns_a_new_list_each_time(t06):
    a = t06.candidates("tcp", 80)
    a.clear()
    assert _sids(t06, "tcp", 80) == [1, 2, 3, 5]


def test_needs_frozen_repository():
    repo = RuleRepository()
    repo.add(parse_rule(T06_RULES[0]).rule)
    with pytest.raises(ValueError):
        RuleIndexer(repo)
    repo.freeze()
    assert len(RuleIndexer(repo)) == 1


def test_index_is_a_superset_filter_not_a_matcher():
    # source port, IPs and content are not looked at: the rule is still a candidate
    idx = _index(['alert tcp 10.0.0.1 9999 -> 192.168.0.1 80 (msg:"a"; content:"zzz"; sid:1;)'])
    assert _sids(idx, "tcp", 80) == [1]
