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


def mk(cb=None, **extra):
    out = []

    def on_export(f):
        out.append(f)
        if cb:
            cb(f)

    flow = {"sweep_interval_sec": 1e9, "udp_idle_timeout_sec": 1e6, "tcp_idle_timeout_sec": 1e6,
            "tcp_handshake_timeout_sec": 1e6, "tcp_closed_linger_sec": 1e6, **extra}
    return FlowTracker({"flow": flow}, on_export=on_export), out


def feed(tr, sp, seq, ts=0.0):
    for fl, fr in seq:
        tr.update(pkt("TCP", fl, fr, sp=sp, ts=ts))


HS = [(["SYN"], "C")]
EST = HS + [(["SYN", "ACK"], "S"), (["ACK"], "C")]
CLOSING = EST + [(["FIN", "ACK"], "C")]
CLOSED = EST + [(["FIN", "ACK"], "C"), (["FIN", "ACK"], "S")]
RESET = EST + [(["RST"], "S")]


def test_flush_exports_everything_and_empties_the_table():
    tr, out = mk()
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    assert tr.flush() == 3
    assert tr.active_flow_count() == 0 and len(out) == 3


def test_flush_on_empty_table():
    tr, out = mk()
    assert tr.flush() == 0 and out == []


@pytest.mark.parametrize("seq,reason", [
    (HS, "flush"), (EST, "flush"), (CLOSING, "flush"),
    (CLOSED, "tcp_closed"), (RESET, "tcp_reset"),
])
def test_close_reason_for_tcp_states(seq, reason):
    tr, out = mk()
    feed(tr, 1, seq)
    tr.flush()
    assert out[0].close_reason == reason


def test_udp_flow_gets_flush_reason():
    tr, out = mk()
    tr.update(pkt(ts=0))
    tr.flush()
    assert out[0].close_reason == "flush" and out[0].state == "ACTIVE"


def test_flush_order_is_least_recently_active_first():
    tr, out = mk()
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    tr.update(pkt(sp=1, ts=4))
    tr.flush()
    assert [f.endpoint_a["port"] for f in out] == [2, 3, 1]


def test_flushed_flow_keeps_its_numbers():
    tr, out = mk()
    feed(tr, 1, EST, ts=0)
    tr.flush()
    f = out[0]
    assert (f.state, f.packet_count, f.syn_count, f.ack_count) == ("ESTABLISHED", 3, 2, 2)


def test_flush_is_idempotent_no_duplicate_exports():
    tr, out = mk()
    tr.update(pkt(ts=0))
    assert tr.flush() == 1
    assert tr.flush() == 0
    assert len(out) == 1


def test_each_flow_is_exported_exactly_once_across_sweep_and_flush():
    tr, out = mk(udp_idle_timeout_sec=5)
    tr.update(pkt(sp=1, ts=0))
    tr.update(pkt(sp=2, ts=100))
    tr.sweep()
    tr.flush()
    ids = [f.flow_id for f in out]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert [f.close_reason for f in out] == ["idle_timeout", "flush"]


def test_failing_callback_does_not_stop_remaining_flushes():
    calls = []

    def boom(f):
        calls.append(f.endpoint_a["port"])
        raise RuntimeError("x")

    tr, out = mk(cb=boom)
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    assert tr.flush() == 3 and calls == [1, 2, 3] and tr.active_flow_count() == 0


def test_callback_sees_shrinking_table():
    seen, holder = [], {}
    tr, out = mk(cb=lambda f: seen.append(holder["tr"].active_flow_count()))
    holder["tr"] = tr
    for sp in (1, 2, 3):
        tr.update(pkt(sp=sp, ts=sp))
    tr.flush()
    assert seen == [2, 1, 0]


def test_flush_without_export_callback():
    tr = FlowTracker({})
    tr.update(pkt(ts=0))
    assert tr.flush() == 1 and tr.active_flow_count() == 0


def test_tracker_keeps_working_after_flush():
    tr, out = mk()
    first = tr.update(pkt(ts=0))
    tr.flush()
    again = tr.update(pkt(ts=1))
    assert again.flow_id != first.flow_id and tr.active_flow_count() == 1


def test_unswept_expired_flow_is_still_flushed_with_flush_reason():
    tr, out = mk(tcp_handshake_timeout_sec=3)
    feed(tr, 1, HS, ts=0)
    tr.flush()
    assert out[0].close_reason == "flush"


def test_flushed_flow_duration_is_last_seen_minus_start():
    tr, out = mk()
    tr.update(pkt(ts=0))
    tr.update(pkt(ts=2.5))
    tr.flush()
    assert out[0].duration == 2.5