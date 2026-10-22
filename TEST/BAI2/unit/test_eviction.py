import pytest
from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

S = ("10.0.0.2", 80)


def pkt(proto="UDP", flags=None, frm="C", ts=0.0, sp=1, **kw):
    c = ("10.0.0.1", sp)
    a, b = (c, S) if frm == "C" else (S, c)
    d = dict(packet_id=1, timestamp=100.0 + ts, src_ip=a[0], src_port=a[1],
             dst_ip=b[0], dst_port=b[1], network_protocol="IPv4",
             transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": flags} if proto == "TCP" else {})
    d.update(kw)
    return IDSEvent(**d)


def mk(max_flows=3, cb=None, **extra):
    out = []

    def on_export(f):
        out.append(f)
        if cb:
            cb(f)

    flow = {"sweep_interval_sec": 1e9, "udp_idle_timeout_sec": 1e6, "tcp_idle_timeout_sec": 1e6,
            "tcp_handshake_timeout_sec": 1e6, "tcp_closed_linger_sec": 1e6, **extra}
    if max_flows is not None:
        flow["max_active_flows"] = max_flows
    return FlowTracker({"flow": flow}, on_export=on_export), out


def ports(out):
    return [f.endpoint_a["port"] for f in out]


def test_table_never_exceeds_limit_and_oldest_is_evicted():
    tr, out = mk(3)
    for sp in (1, 2, 3, 4):
        tr.update(pkt(sp=sp, ts=sp))
    assert tr.active_flow_count() == 3
    assert ports(out) == [1] and out[0].close_reason == "evicted"


def test_eviction_is_least_recently_active_not_oldest_created():
    tr, out = mk(3)
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    tr.update(pkt(sp=1, ts=4))          # flow 1 becomes the most recent
    tr.update(pkt(sp=4, ts=5))          # evicts flow 2
    assert ports(out) == [2]


def test_packet_for_existing_flow_at_capacity_does_not_evict():
    tr, out = mk(3)
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    tr.update(pkt(sp=2, ts=4))
    assert out == [] and tr.active_flow_count() == 3


def test_evicted_flow_keeps_its_numbers_and_state():
    tr, out = mk(2)
    for fl, fr in ((["SYN"], "C"), (["SYN", "ACK"], "S"), (["ACK"], "C")):
        tr.update(pkt("TCP", fl, fr, sp=1, ts=0))
    tr.update(pkt(sp=2, ts=1))
    tr.update(pkt(sp=3, ts=2))
    ev = out[0]
    assert ev.close_reason == "evicted" and ev.state == "ESTABLISHED" and ev.packet_count == 3


def test_evicted_flow_returning_later_starts_a_new_flow():
    tr, out = mk(2)
    first = tr.update(pkt(sp=1, ts=0))
    tr.update(pkt(sp=2, ts=1))
    tr.update(pkt(sp=3, ts=2))
    again = tr.update(pkt(sp=1, ts=3))
    assert again.flow_id != first.flow_id
    assert tr.active_flow_count() == 2


def test_callback_runs_before_new_flow_is_added():
    seen, holder = [], {}
    tr, out = mk(2, cb=lambda f: seen.append(holder["tr"].active_flow_count()))
    holder["tr"] = tr
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    assert seen == [1]


def test_limit_of_one():
    tr, out = mk(1)
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    assert tr.active_flow_count() == 1 and ports(out) == [1, 2]


def test_syn_flood_stays_bounded():
    tr, out = mk(100)
    for sp in range(1, 1001):
        tr.update(pkt("TCP", ["SYN"], sp=sp, ts=sp * 0.001))
    assert tr.active_flow_count() == 100
    assert len(out) == 900 and {f.close_reason for f in out} == {"evicted"}
    assert ports(out) == list(range(1, 901))


def test_port_reuse_frees_a_slot_so_no_extra_eviction():
    tr, out = mk(2)
    for fl, fr in ((["SYN"], "C"), (["SYN", "ACK"], "S"), (["ACK"], "C"), (["RST"], "S")):
        tr.update(pkt("TCP", fl, fr, sp=1, ts=0))
    tr.update(pkt(sp=2, ts=1))
    tr.update(pkt("TCP", ["SYN"], sp=1, ts=2))
    assert [f.close_reason for f in out] == ["port_reuse"] and tr.active_flow_count() == 2


def test_lazy_expiry_frees_a_slot_so_no_extra_eviction():
    tr, out = mk(2, udp_idle_timeout_sec=5)
    tr.update(pkt(sp=1, ts=0))
    tr.update(pkt(sp=2, ts=1))
    tr.update(pkt(sp=1, ts=10))
    assert [f.close_reason for f in out] == ["idle_timeout"] and tr.active_flow_count() == 2


def test_default_limit_matches_settings_yaml():
    tr, out = mk(None)
    for sp in range(1, 10_002):
        tr.update(pkt(sp=sp, ts=0))
    assert out == [] and tr.active_flow_count() == 10_001


@pytest.mark.parametrize("bad", ["x", None, 0, -1, True, 2.5, float("nan")])
def test_invalid_limit_uses_default(bad):
    tr, out = mk(bad)
    for sp in range(1, 10_002):
        tr.update(pkt(sp=sp, ts=0))
    assert out == [] and tr.active_flow_count() == 10_001


def test_failing_callback_does_not_block_admission_or_hang():
    def boom(_):
        raise RuntimeError("x")

    tr, out = mk(2, cb=boom)
    for sp in (1, 2, 3, 4):
        tr.update(pkt(sp=sp, ts=sp))
    assert tr.active_flow_count() == 2 and ports(out) == [1, 2]


def test_eviction_does_not_happen_for_invalid_events():
    tr, out = mk(1)
    tr.update(pkt(sp=1, ts=0))
    tr.update(pkt(sp=2, ts=1, preprocess_status="invalid"))
    assert out == [] and tr.active_flow_count() == 1


def test_new_flow_after_eviction_is_tracked_normally():
    tr, out = mk(1)
    tr.update(pkt(sp=1, ts=0))
    ev = tr.update(pkt("TCP", ["SYN"], sp=2, ts=1))
    assert ev.flow_state == "HANDSHAKE" and ev.direction == "forward"


def test_inconsistent_table_entry_cannot_cause_an_endless_loop():
    from src.flow.flow_table import FlowEntry
    from src.models.flow import Flow
    tr, out = mk(1)
    bogus = Flow(flow_id="x", protocol="UDP", endpoint_a={"ip": "1.1.1.1", "port": 1},
                 endpoint_b={"ip": "2.2.2.2", "port": 2}, start_time=1.0, last_seen=1.0, state="ACTIVE")
    tr.table.add(("not", "the", "real", "key"), FlowEntry(bogus))
    tr.update(pkt(sp=9, ts=5))
    assert tr.active_flow_count() == 1