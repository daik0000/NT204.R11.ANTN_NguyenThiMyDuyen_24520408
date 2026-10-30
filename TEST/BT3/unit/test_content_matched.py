import pytest

from pcap_builder import tcp_packet, write_pcap
from src.capture.pcap_reader import read_pcap
from src.engine.content_matcher import content_fn, match_contents
from src.engine.matcher import match_rule
from src.models.detection import Detection
from src.models.event import IDSEvent
from src.pipeline.pipeline import _parse_packet_layers
from src.rules.validator import parse_rule

GET = b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"


def rule(options, header="alert tcp any any -> any 80"):
    result = parse_rule(f'{header} (msg:"x"; {options} sid:1;)')
    assert result.status == "valid", result
    return result.rule


def event(payload, port=80):
    return IDSEvent(packet_id=1, timestamp=1.0, src_ip="10.0.0.1", src_port=40000, dst_ip="10.0.0.2", dst_port=port,
                    network_protocol="IPv4", transport_protocol="TCP", raw_length=60, preprocess_status="valid",
                    payload=payload, transport_fields={"flags": ["PSH", "ACK"]})


# --- format ---------------------------------------------------------------------------------------------------

def test_http_get_traversal_offset_5_length_3():
    # G E T <space> / -> the first "../" starts at byte 5
    assert match_contents(rule('content:"../";'), GET) == [
        {"keyword": "content", "value": "../", "offset": 5, "length": 3}]


def test_one_dict_per_content_in_rule_order():
    r = rule('content:"GET"; content:"passwd"; distance:0; content:"HTTP/1.1"; distance:0;')
    assert match_contents(r, GET) == [
        {"keyword": "content", "value": "GET", "offset": 0, "length": 3},
        {"keyword": "content", "value": "passwd", "offset": 15, "length": 6},
        {"keyword": "content", "value": "HTTP/1.1", "offset": 22, "length": 8},
    ]


def test_no_match_gives_none():
    assert match_contents(rule('content:"admin";'), GET) is None
    assert match_contents(rule('content:"GET"; content:"zzz"; distance:0;'), GET) is None


def test_value_is_the_text_from_the_rule_not_the_bytes():
    hits = match_contents(rule('content:"GE|54| /";'), GET)
    assert hits == [{"keyword": "content", "value": "GE|54| /", "offset": 0, "length": 5}]
    assert isinstance(hits[0]["value"], str)


def test_nocase_reports_the_rule_text_and_the_real_position():
    hits = match_contents(rule('content:"ETC"; nocase;'), GET)
    assert hits == [{"keyword": "content", "value": "ETC", "offset": 11, "length": 3}]
    assert GET[11:14] == b"etc"


def test_offset_is_absolute_in_the_payload_not_relative_to_the_window():
    # window [12, 32) starts inside the payload; the reported offset is still counted from byte 0
    hits = match_contents(rule('content:"passwd"; offset:12; depth:20;'), GET)
    assert hits[0]["offset"] == 15 and GET[15:21] == b"passwd"


def test_offsets_come_from_the_successful_backtracking_path():
    payload = b"BBB----BBB-CCC"
    r = rule('content:"BBB"; content:"CCC"; distance:1; within:3;')
    # the first BBB (offset 0) leads nowhere; the second (offset 7) does
    assert match_contents(r, payload) == [
        {"keyword": "content", "value": "BBB", "offset": 7, "length": 3},
        {"keyword": "content", "value": "CCC", "offset": 11, "length": 3},
    ]


def test_rule_without_content_gives_empty_list():
    assert match_contents(rule(""), GET) == []


@pytest.mark.parametrize("payload", [None, b"", "text"])
def test_no_payload_gives_none_for_a_rule_with_content(payload):
    assert match_contents(rule('content:"a";'), payload) is None


def test_every_dict_is_accepted_by_detection():
    hits = match_contents(rule('content:"GET"; content:"../"; distance:1;'), GET)
    det = Detection(sid=1, rev=1, msg="x", priority=3, timestamp=1.0, packet_id=1, src_ip="10.0.0.1", src_port=1,
                    dst_ip="10.0.0.2", dst_port=80, protocol="TCP", matched=hits)
    assert det.to_dict()["matched"] == hits


# --- plugged into match_rule ------------------------------------------------------------------------------------------

def test_content_fn_reads_the_event_payload():
    assert content_fn(rule('content:"../";'), event(GET)) == match_contents(rule('content:"../";'), GET)
    assert content_fn(rule('content:"../";'), event(None)) is None


def test_match_rule_with_content_fn_end_to_end():
    result = match_rule(rule('content:"../";'), event(GET), None, content_fn)
    assert result.matched is True and result.failed_stage is None
    assert result.matches == [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]


def test_match_rule_content_failure_is_reported_as_content_stage():
    result = match_rule(rule('content:"admin";'), event(GET), None, content_fn)
    assert (result.matched, result.failed_stage, result.matches) == (False, "content", [])


def test_match_rule_does_not_search_content_when_the_header_fails():
    calls = []

    def spy(r, e):
        calls.append(1)
        return content_fn(r, e)

    result = match_rule(rule('content:"../";'), event(GET, port=8080), None, spy)
    assert result.failed_stage == "header" and calls == []


def test_http_get_through_the_real_parser(tmp_path):
    frame = tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "PA", ts=1.0, payload=GET)
    path = write_pcap([frame], str(tmp_path / "t.pcap"))
    (ts, raw), = list(read_pcap(path))
    parsed = _parse_packet_layers(ts, raw, 1)
    assert parsed.status == "OK" and parsed.payload == GET
    result = match_rule(rule('content:"../";'), parsed, None, content_fn)
    assert result.matches == [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]
