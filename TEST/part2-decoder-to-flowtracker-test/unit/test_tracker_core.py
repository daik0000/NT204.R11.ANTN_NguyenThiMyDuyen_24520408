import pytest

from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker


def ev(src=("10.0.0.1", 40000), dst=("10.0.0.2", 80), proto="TCP", ts=100.0, **kw):
    d = dict(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid")
    d.update(kw)
    return IDSEvent(**d)


def tracker():
    return FlowTracker({})


def test_first_packet_creates_flow_and_tags_event():
    t = tracker()
    e = t.update(ev())
    assert e.flow_id is not None and e.direction == "forward" and len(t.table) == 1
    assert e.error_info is None


def test_reply_joins_same_flow_as_backward():
    t = tracker()
    a = t.update(ev(ts=1.0))
    b = t.update(ev(src=("10.0.0.2", 80), dst=("10.0.0.1", 40000), ts=2.0))
    assert b.flow_id == a.flow_id and b.direction == "backward" and len(t.table) == 1
    assert t.table.items()[0][1].flow.last_seen == 2.0


def test_tcp_and_udp_with_same_endpoints_are_two_flows():
    t = tracker()
    a = t.update(ev(proto="TCP"))
    b = t.update(ev(proto="UDP"))
    assert a.flow_id != b.flow_id and len(t.table) == 2


def test_udp_flow_is_active_and_tcp_state_is_a_documented_value():
    t = tracker()
    t.update(ev(proto="UDP"))
    t.update(ev(src=("10.0.0.9", 1), proto="TCP"))
    states = {e.flow.protocol: e.flow.state for _, e in t.table.items()}
    assert states["UDP"] == "ACTIVE" and states["TCP"] in {"HANDSHAKE", "ESTABLISHED"}


@pytest.mark.parametrize("kw", [
    dict(preprocess_status="invalid"), dict(transport_protocol=None), dict(transport_protocol="ICMP"),
    dict(src_ip=None), dict(dst_ip=None), dict(src_port=None), dict(dst_port=None),
])
def test_untrackable_events_are_returned_untouched_without_creating_a_flow(kw):
    t = tracker()
    e = t.update(ev(**kw))
    assert e.flow_id is None and e.direction is None and len(t.table) == 0 and e.error_info is None


def test_ignored_status_event_still_creates_flow():
    t = tracker()
    t.update(ev(status="IGNORED"))
    assert len(t.table) == 1


def test_application_protocol_is_none_or_upper_case():
    t = tracker()
    t.update(ev(app_protocol=None))
    t.update(ev(src=("10.0.0.8", 5), app_protocol="HTTP"))
    assert {e.flow.application_protocol for _, e in t.table.items()} == {None, "HTTP"}


def test_untrackable_events_must_not_advance_the_clock():
    t = tracker()
    t.update(ev(ts=100.0))
    t.update(ev(ts=float("inf"), preprocess_status="invalid"))
    t.update(ev(ts=9e12, preprocess_status="invalid"))
    assert t.clock == 100.0


def test_export_removes_flow_sets_reason_and_calls_back_once():
    got = []
    t = FlowTracker({}, on_export=got.append)
    t.update(ev(ts=1.0))
    t.update(ev(ts=4.0))
    entry = t.table.items()[0][1]
    t._export_flow(entry, "flush")
    assert len(t.table) == 0 and len(got) == 1
    assert got[0].close_reason == "flush" and got[0].duration == 3.0
    t._export_flow(entry, "flush")                      # already gone: no second callback
    assert len(got) == 1


def test_failing_callback_does_not_raise_and_flow_is_still_removed():
    def boom(flow):
        raise RuntimeError("disk full")

    t = FlowTracker({}, on_export=boom)
    t.update(ev())
    t._export_flow(t.table.items()[0][1], "flush")      # must not raise
    assert len(t.table) == 0