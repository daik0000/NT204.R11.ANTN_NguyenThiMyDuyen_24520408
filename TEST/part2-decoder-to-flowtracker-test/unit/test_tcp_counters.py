import pytest

from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

A = ("10.0.0.1", 40000)
B = ("10.0.0.2", 80)


def ev(flags, src=A, dst=B, proto="TCP", ts=100.0, **kw):
    d = dict(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": flags})
    d.update(kw)
    return IDSEvent(**d)


def feed(*packets):
    t = FlowTracker({})
    for p in packets:
        t.update(p)
    return t


def flow_of(t):
    return t.table.items()[0][1].flow


def counts(t):
    f = flow_of(t)
    return (f.syn_count, f.ack_count, f.fin_count, f.rst_count)


def test_each_counter_is_the_number_of_packets_carrying_that_flag():
    t = feed(ev(["SYN"]), ev(["SYN", "ACK"], src=B, dst=A), ev(["ACK"]), ev(["PSH", "ACK"]),
             ev(["FIN", "ACK"]), ev(["FIN", "ACK"], src=B, dst=A), ev(["ACK"]))
    assert counts(t) == (2, 6, 2, 0)


def test_syn_ack_increments_both_counters():
    assert counts(feed(ev(["SYN", "ACK"]))) == (1, 1, 0, 0)


def test_rst_counter_and_scan_shapes():
    assert counts(feed(ev(["SYN"]), ev(["RST", "ACK"], src=B, dst=A))) == (1, 1, 0, 1)
    assert counts(feed(ev(["SYN"]))) == (1, 0, 0, 0)


def test_pure_ack_without_payload_is_counted():
    t = feed(ev(["ACK"], payload=b""))
    assert counts(t) == (0, 1, 0, 0) and flow_of(t).payload_byte_count == 0


def test_psh_urg_and_unknown_flags_are_not_counted():
    assert counts(feed(ev(["PSH", "URG", "ECE", "CWR", "BOGUS"]))) == (0, 0, 0, 0)


def test_duplicate_and_lower_case_flags_count_once_per_packet():
    assert counts(feed(ev(["SYN", "syn", "Syn"]))) == (1, 0, 0, 0)


@pytest.mark.parametrize("flags", [None, [], "SYN", "SYN-ACK", 5, {"SYN": 1}])
def test_missing_or_malformed_flags_count_nothing_but_the_packet_still_counts(flags):
    t = feed(ev(flags))
    f = flow_of(t)
    assert counts(t) == (0, 0, 0, 0)
    assert f.packet_count == 1 and f.fwd_packet_count == 1


def test_transport_fields_not_a_dict_is_tolerated():
    assert counts(feed(ev(["SYN"], transport_fields=None))) == (0, 0, 0, 0)
    assert counts(feed(ev(["SYN"], transport_fields=["junk"]))) == (0, 0, 0, 0)


def test_tuple_and_set_flags_are_accepted():
    assert counts(feed(ev(("SYN",)), ev({"ACK"}))) == (1, 1, 0, 0)


def test_udp_flow_never_counts_tcp_flags():
    assert counts(feed(ev(["SYN", "ACK", "FIN", "RST"], proto="UDP"))) == (0, 0, 0, 0)


def test_untrackable_event_counts_nothing():
    assert counts(feed(ev(["SYN"]), ev(["RST"], preprocess_status="invalid"))) == (1, 0, 0, 0)