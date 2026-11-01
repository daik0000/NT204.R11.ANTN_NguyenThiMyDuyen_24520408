import json
import time

import pytest

from src.engine.detection import make_detection
from src.engine.evaluator import EvaluationEngine
from src.engine.stats import EvaluationStats
from src.models.detection import Detection
from src.models.engine_types import FlowContext
from src.models.event import IDSEvent
from src.models.rule import ContentSpec, IpSpec, PortSpec, Rule
from src.rules.repository import RuleRepository
from src.rules.validator import DEFAULT_PRIORITY, parse_rule


def rule(options='content:"../";', sid=1000001, header="alert tcp any any -> any 80"):
    result = parse_rule(f'{header} (msg:"WEB traversal"; {options} sid:{sid};)')
    assert result.status == "valid", result
    return result.rule


def pkt(**kw):
    d = dict(packet_id=42, timestamp=1700000000.25, src_ip="10.0.0.1", src_port=40000, dst_ip="10.0.0.2", dst_port=80,
             network_protocol="IPv4", transport_protocol="TCP", raw_length=60, preprocess_status="valid",
             payload=b"GET /../ HTTP/1.1", app_protocol="HTTP", flow_id="flow-1", direction="forward",
             transport_fields={"flags": ["PSH", "ACK"]})
    d.update(kw)
    return IDSEvent(**d)


def ctx(role="to_server", flow_id="flow-1"):
    return FlowContext(flow_id=flow_id, protocol="TCP", state="ESTABLISHED", role=role, established=True,
                       midstream=False, direction="forward")


HIT = [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]


# --- every field -------------------------------------------------------------------------------------------------

def test_all_fields_are_filled():
    r = rule('content:"../"; rev:4; classtype:web-application-attack; priority:2;')
    d = make_detection(r, pkt(), ctx(), HIT)
    assert isinstance(d, Detection)
    assert d.to_dict() == {
        "sid": 1000001, "rev": 4, "msg": "WEB traversal", "priority": 2, "classtype": "web-application-attack",
        "timestamp": 1700000000.25, "packet_id": 42,
        "src_ip": "10.0.0.1", "src_port": 40000, "dst_ip": "10.0.0.2", "dst_port": 80, "protocol": "TCP",
        "application_protocol": "HTTP", "flow_id": "flow-1", "flow_direction": "to_server",
        "matched": HIT,
    }


def test_rule_without_classtype_gives_none():
    assert make_detection(rule(), pkt(), ctx(), HIT).classtype is None


def test_rule_without_content_gives_the_header_marker():
    r = rule("flags:PA;")
    assert make_detection(r, pkt(), ctx(), []).matched == [{"keyword": "header"}]
    assert make_detection(r, pkt(), ctx(), [{"keyword": "header"}]).matched == [{"keyword": "header"}]


def test_priority_comes_from_the_rule_the_parser_filled_in():
    assert make_detection(rule(), pkt(), ctx(), HIT).priority == 3                # default_priority from the Parser
    assert make_detection(rule("priority:1; content:\"x\";"), pkt(), ctx(), HIT).priority == 1


def test_hand_built_rule_without_priority_uses_the_default():
    r = Rule(action="alert", protocol="tcp", src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535), direction="->",
             dst_ip=IpSpec(any=True), dst_port=PortSpec(0, 65535), msg="m", sid=9,
             contents=(ContentSpec("a", b"a"),))
    assert r.priority is None
    assert make_detection(r, pkt(), ctx(), HIT).priority == DEFAULT_PRIORITY == 3


# --- packet and flow context --------------------------------------------------------------------------------------------------

def test_timestamp_and_packet_id_are_the_events():
    d = make_detection(rule(), pkt(timestamp=12.5, packet_id=99), ctx(), HIT)
    assert (d.timestamp, d.packet_id) == (12.5, 99)


def test_protocol_and_application_protocol():
    udp = pkt(transport_protocol="UDP", app_protocol="DNS", dst_port=53)
    d = make_detection(rule(header="alert udp any any -> any 53"), udp, None, HIT)
    assert (d.protocol, d.application_protocol) == ("UDP", "DNS")
    assert make_detection(rule(), pkt(app_protocol=None), ctx(), HIT).application_protocol is None
    assert make_detection(rule(), pkt(app_protocol="UNKNOWN"), ctx(), HIT).application_protocol == "UNKNOWN"
    assert make_detection(rule(), pkt(transport_protocol="tcp"), ctx(), HIT).protocol == "TCP"


@pytest.mark.parametrize("role", ["to_server", "to_client"])
def test_flow_direction_is_the_role_not_forward_or_backward(role):
    d = make_detection(rule(), pkt(direction="backward"), ctx(role=role), HIT)
    assert d.flow_direction == role


def test_flow_id_comes_from_the_context():
    assert make_detection(rule(), pkt(flow_id="from-event"), ctx(flow_id="from-ctx"), HIT).flow_id == "from-ctx"


def test_without_a_context_flow_id_comes_from_the_event_and_direction_is_none():
    d = make_detection(rule(), pkt(flow_id="from-event"), None, HIT)
    assert (d.flow_id, d.flow_direction) == ("from-event", None)
    d = make_detection(rule(), pkt(flow_id=None), None, HIT)
    assert (d.flow_id, d.flow_direction) == (None, None)


# --- purity ----------------------------------------------------------------------------------------------------------------------

def test_prints_and_logs_nothing(capsys, caplog):
    import logging
    with caplog.at_level(logging.DEBUG):
        make_detection(rule(), pkt(), ctx(), HIT)
    out = capsys.readouterr()
    assert out.out == "" and out.err == "" and caplog.records == []


def test_reads_no_clock(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("the clock must not be read")
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(time, "monotonic", forbidden)
    assert make_detection(rule(), pkt(), ctx(), HIT).timestamp == 1700000000.25


def test_writes_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_detection(rule(), pkt(), ctx(), HIT)
    assert list(tmp_path.iterdir()) == []


def test_does_not_modify_its_inputs():
    r, e, matches = rule(), pkt(), [dict(HIT[0])]
    before = (r, e.to_dict(), [dict(m) for m in matches])
    make_detection(r, e, ctx(), matches)
    assert (r, e.to_dict(), matches) == before


def test_matches_list_is_copied():
    matches = [dict(HIT[0])]
    d = make_detection(rule(), pkt(), ctx(), matches)
    matches[0]["offset"] = 999
    matches.append({"keyword": "header"})
    assert d.matched == HIT


def test_match_dicts_are_not_shared_between_detections():
    shared = [dict(HIT[0])]
    a, b = make_detection(rule(sid=1), pkt(), ctx(), shared), make_detection(rule(sid=2), pkt(), ctx(), shared)
    shared[0]["offset"] = 999
    a.matched[0]["length"] = 777
    assert b.matched == HIT and a.matched[0]["offset"] == 5


def test_two_detections_from_one_event_do_not_share_state():
    e = pkt()
    a, b = make_detection(rule(sid=1), e, ctx(), HIT), make_detection(rule(sid=2), e, ctx(), HIT)
    a.matched.append({"keyword": "header"})
    assert b.matched == HIT and a.sid == 1 and b.sid == 2


def test_to_dict_is_json_serialisable():
    d = make_detection(rule(), pkt(), ctx(), HIT)
    assert json.loads(json.dumps(d.to_dict())) == d.to_dict()


# --- errors -----------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("proto", [None, "ICMP", ""])
def test_an_event_without_tcp_or_udp_cannot_become_a_detection(proto):
    with pytest.raises(ValueError):
        make_detection(rule(), pkt(transport_protocol=proto), ctx(), HIT)


# --- from the engine's results ---------------------------------------------------------------------------------------------------------------

def test_detections_from_engine_results_keep_rule_order():
    repo = RuleRepository()
    for line in ['alert tcp any any -> any 80 (msg:"a"; content:"GET"; sid:30;)',
                 'alert tcp any any -> any 80 (msg:"b"; flags:PA; sid:10;)']:
        repo.add(parse_rule(line).rule)
    event = pkt()
    results = EvaluationEngine(repo, EvaluationStats(), None).evaluate(event, ctx())
    detections = [make_detection(res.rule, event, ctx(), res.matches) for res in results]
    assert [d.sid for d in detections] == [30, 10]
    assert detections[0].matched == [{"keyword": "content", "value": "GET", "offset": 0, "length": 3}]
    assert detections[1].matched == [{"keyword": "header"}]
