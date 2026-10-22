import pytest

from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

A = ("10.0.0.1", 40000)
B = ("10.0.0.2", 80)


def ev(src=A, dst=B, proto="TCP", ts=100.0, **kw):
    d = dict(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"")
    d.update(kw)
    return IDSEvent(**d)


def only_flow(t):
    items = t.table.items()
    assert len(items) == 1
    return items[0][1].flow


def test_counters_split_by_direction_and_sum_to_totals():
    t = FlowTracker({})
    t.update(ev(raw_length=60))
    t.update(ev(src=B, dst=A, raw_length=74))
    t.update(ev(raw_length=54))
    t.update(ev(src=B, dst=A, raw_length=200))
    f = only_flow(t)
    assert (f.packet_count, f.byte_count) == (4, 388)
    assert (f.fwd_packet_count, f.fwd_byte_count) == (2, 114)
    assert (f.bwd_packet_count, f.bwd_byte_count) == (2, 274)
    assert f.fwd_byte_count + f.bwd_byte_count == f.byte_count


def test_payload_bytes_come_from_the_raw_payload_not_from_payload_length():
    t = FlowTracker({})
    t.update(ev(payload=b"", payload_length=20))               # pure ACK: L4 header only
    t.update(ev(payload=b"GET / HTTP/1.1\r\n\r\n", payload_length=38))
    t.update(ev(payload=None, payload_length=20))
    assert only_flow(t).payload_byte_count == 18


def test_timestamps_follow_min_max_but_flow_id_is_stable():
    t = FlowTracker({})
    first = t.update(ev(ts=10.0))
    t.update(ev(ts=12.5))
    late = t.update(ev(ts=9.0))
    f = only_flow(t)
    assert (f.start_time, f.last_seen, f.duration) == (9.0, 12.5, 3.5)
    assert first.flow_id == late.flow_id == f.flow_id


def test_missing_raw_length_is_counted_as_zero_bytes_but_the_packet_still_counts():
    t = FlowTracker({})
    t.update(ev(raw_length=None))
    f = only_flow(t)
    assert (f.packet_count, f.byte_count, f.fwd_packet_count) == (1, 0, 1)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -5, True, "60"])
def test_garbage_raw_length_never_corrupts_the_counters(bad):
    t = FlowTracker({})
    e = t.update(ev(raw_length=bad))
    f = only_flow(t)
    assert e.error_info is None
    assert (f.packet_count, f.byte_count, f.fwd_packet_count, f.fwd_byte_count) == (1, 0, 1, 0)


def test_application_protocol_priority_specific_over_unknown_over_none():
    t = FlowTracker({})
    t.update(ev(app_protocol=None))
    assert only_flow(t).application_protocol is None
    t.update(ev(app_protocol="UNKNOWN"))
    assert only_flow(t).application_protocol == "UNKNOWN"
    t.update(ev(app_protocol="http"))
    assert only_flow(t).application_protocol == "HTTP"
    t.update(ev(app_protocol="DNS"))
    assert only_flow(t).application_protocol == "HTTP"          # first specific value wins
    t.update(ev(app_protocol="UNKNOWN"))
    t.update(ev(app_protocol=None))
    assert only_flow(t).application_protocol == "HTTP"


def test_udp_flow_counts_both_directions():
    t = FlowTracker({})
    t.update(ev(src=("10.0.0.1", 5353), dst=("8.8.8.8", 53), proto="UDP",
                raw_length=80, payload=b"q" * 30, app_protocol="DNS"))
    t.update(ev(src=("8.8.8.8", 53), dst=("10.0.0.1", 5353), proto="UDP", ts=100.2,
                raw_length=120, payload=b"r" * 70, app_protocol="DNS"))
    f = only_flow(t)
    assert (f.packet_count, f.byte_count, f.payload_byte_count) == (2, 200, 100)
    assert (f.fwd_packet_count, f.bwd_packet_count, f.application_protocol, f.state) == (1, 1, "DNS", "ACTIVE")
    assert (f.syn_count, f.ack_count, f.fin_count, f.rst_count) == (0, 0, 0, 0)


def test_untrackable_event_changes_no_statistics():
    t = FlowTracker({})
    t.update(ev())
    t.update(ev(preprocess_status="invalid", raw_length=999))
    assert only_flow(t).packet_count == 1 and only_flow(t).byte_count == 60