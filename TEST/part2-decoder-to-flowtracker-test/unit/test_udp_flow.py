import pytest
from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

C = ("10.0.0.1", 50000)
D = ("8.8.8.8", 53)


def udp(frm="C", ts=100.0, raw=80, payload=b"", **kw):
    src, dst = (C, D) if frm == "C" else (D, C)
    d = dict(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1],
             dst_ip=dst[0], dst_port=dst[1], network_protocol="IPv4",
             transport_protocol="UDP", raw_length=raw, preprocess_status="valid",
             payload=payload, transport_fields={})
    d.update(kw)
    return IDSEvent(**d)


def run(pkts):
    out = []
    tr = FlowTracker({}, on_export=out.append)
    evs = [tr.update(p) for p in pkts]
    return tr, evs, out


def only_flow(tr):
    return next(e for _, e in tr.table.items()).flow


def test_udp_flow_is_active_from_first_packet():
    tr, evs, _ = run([udp()])
    assert only_flow(tr).state == "ACTIVE"
    assert evs[0].flow_state == "ACTIVE"
    assert evs[0].direction == "forward"


def test_dns_query_and_response_share_one_flow():
    tr, evs, _ = run([udp("C", 100.0, 70, b"q"), udp("S", 100.05, 120, b"resp")])
    assert len(tr.table) == 1
    assert evs[0].flow_id == evs[1].flow_id
    assert (evs[0].direction, evs[1].direction) == ("forward", "backward")
    f = only_flow(tr)
    assert (f.fwd_packet_count, f.bwd_packet_count) == (1, 1)
    assert (f.fwd_byte_count, f.bwd_byte_count) == (70, 120)
    assert f.byte_count == 190 and f.payload_byte_count == 5


def test_udp_state_stays_active_after_many_packets():
    tr, _, _ = run([udp("C" if i % 2 == 0 else "S", 100 + i) for i in range(10)])
    assert only_flow(tr).state == "ACTIVE"
    assert only_flow(tr).packet_count == 10


def test_udp_ignores_tcp_flag_counters_even_if_flags_present():
    p = udp(transport_fields={"flags": ["SYN", "ACK", "FIN", "RST"]})
    tr, _, _ = run([p])
    f = only_flow(tr)
    assert (f.syn_count, f.ack_count, f.fin_count, f.rst_count) == (0, 0, 0, 0)
    assert f.midstream is False


def test_udp_syn_like_flags_do_not_trigger_port_reuse():
    tr, evs, out = run([udp(), udp(ts=101, transport_fields={"flags": ["SYN"]})])
    assert out == [] and evs[0].flow_id == evs[1].flow_id


def test_different_udp_ports_make_different_flows():
    tr, evs, _ = run([udp(), udp(src_port=50001)])
    assert len(tr.table) == 2 and evs[0].flow_id != evs[1].flow_id


def test_udp_and_tcp_same_tuple_are_separate_flows():
    tcp = udp(transport_protocol="TCP", transport_fields={"flags": ["SYN"]})
    tr, evs, _ = run([udp(), tcp])
    assert len(tr.table) == 2 and evs[0].flow_id != evs[1].flow_id


def test_udp_app_protocol_dns_recorded():
    tr, _, _ = run([udp(app_protocol="DNS")])
    assert only_flow(tr).application_protocol == "DNS"


def test_udp_flow_to_dict_has_protocol_udp_and_zero_flags():
    tr, _, _ = run([udp("C", 100.0), udp("S", 100.5)])
    d = only_flow(tr).to_dict()
    assert d["protocol"] == "UDP" and d["state"] == "ACTIVE"
    assert d["duration"] == pytest.approx(0.5)
    assert d["syn_count"] == d["ack_count"] == d["fin_count"] == d["rst_count"] == 0