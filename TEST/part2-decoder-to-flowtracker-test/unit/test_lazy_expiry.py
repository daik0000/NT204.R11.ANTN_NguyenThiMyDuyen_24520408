import pytest
from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

C = ("10.0.0.1", 50000)
S = ("10.0.0.2", 80)
CFG = {"flow": {"sweep_interval_sec": 1000, 
                "udp_idle_timeout_sec": 5, 
                "tcp_idle_timeout_sec": 5,
                "tcp_handshake_timeout_sec": 3, 
                "tcp_closed_linger_sec": 2}}


def pkt(proto="TCP", flags=None, frm="C", ts=0.0, **kw):
    src, dst = (C, S) if frm == "C" else (S, C)
    d = dict(packet_id=1, timestamp=100.0 + ts, src_ip=src[0], src_port=src[1],
             dst_ip=dst[0], dst_port=dst[1], network_protocol="IPv4",
             transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": flags} if proto == "TCP" else {})
    d.update(kw)
    return IDSEvent(**d)


def run(pkts, cfg=CFG, cb=None):
    out = []

    def on_export(f):
        out.append(f)
        if cb:
            cb(f)

    tr = FlowTracker(cfg, on_export=on_export)
    evs = [tr.update(p) for p in pkts]
    return tr, evs, out


def est(t=0.0):
    return [pkt(flags=["SYN"], ts=t), pkt(flags=["SYN", "ACK"], frm="S", ts=t + .01),
            pkt(flags=["ACK"], ts=t + .02)]


def test_udp_packet_after_timeout_before_sweep_starts_new_flow():
    tr, evs, out = run([pkt("UDP", ts=0), pkt("UDP", ts=1), pkt("UDP", ts=8)])
    assert len(out) == 1 and out[0].close_reason == "idle_timeout"
    assert out[0].packet_count == 2 and out[0].last_seen == 101.0
    assert evs[2].flow_id != evs[0].flow_id
    assert len(tr.table) == 1


def test_packet_exactly_at_timeout_boundary_stays_in_flow():
    tr, evs, out = run([pkt("UDP", ts=0), pkt("UDP", ts=5)])
    assert out == [] and evs[0].flow_id == evs[1].flow_id


def test_packet_just_after_boundary_splits():
    _, _, out = run([pkt("UDP", ts=0), pkt("UDP", ts=5.001)])
    assert len(out) == 1


def test_tcp_established_expires_with_idle_timeout():
    tr, evs, out = run(est() + [pkt(flags=["ACK"], ts=20)])
    assert out[0].close_reason == "idle_timeout" and out[0].state == "ESTABLISHED"
    assert evs[-1].flow_id != evs[0].flow_id


def test_tcp_handshake_expires_with_handshake_timeout_and_new_syn_gets_new_flow():
    tr, evs, out = run([pkt(flags=["SYN"], ts=0), pkt(flags=["SYN"], ts=10)])
    assert out[0].close_reason == "handshake_timeout"
    assert evs[1].flow_state == "HANDSHAKE" and evs[1].flow_id != evs[0].flow_id


def test_closed_flow_after_linger_exports_tcp_closed_not_port_reuse():
    close = est() + [pkt(flags=["FIN", "ACK"], ts=1), pkt(flags=["FIN", "ACK"], frm="S", ts=1.1),
                     pkt(flags=["ACK"], ts=1.2)]
    tr, evs, out = run(close + [pkt(flags=["SYN"], ts=10)])
    assert out[0].close_reason == "tcp_closed"


def test_reset_flow_after_linger_exports_tcp_reset():
    tr, evs, out = run(est() + [pkt(flags=["RST"], frm="S", ts=1)] + [pkt(flags=["SYN"], ts=10)])
    assert out[0].close_reason == "tcp_reset"


def test_closed_flow_within_linger_still_port_reuse():
    close = est() + [pkt(flags=["RST"], frm="S", ts=1)]
    tr, evs, out = run(close + [pkt(flags=["SYN"], ts=2)])
    assert out[0].close_reason == "port_reuse"


def test_late_ack_within_linger_stays_in_closed_flow():
    close = est() + [pkt(flags=["RST"], frm="S", ts=1)]
    tr, evs, out = run(close + [pkt(flags=["ACK"], ts=2)])
    assert out == [] and evs[-1].flow_id == evs[0].flow_id


def test_expired_flow_exported_before_new_flow_exists():
    sizes, holder = [], {}
    tr = FlowTracker(CFG, on_export=lambda f: sizes.append(len(holder["tr"].table)))
    holder["tr"] = tr
    tr.update(pkt("UDP", ts=0))
    tr.update(pkt("UDP", ts=9))
    assert sizes == [0] and len(tr.table) == 1


def test_duration_of_expired_flow_excludes_idle_wait():
    _, _, out = run([pkt("UDP", ts=0), pkt("UDP", ts=2), pkt("UDP", ts=50)])
    assert out[0].duration == 2.0


def test_out_of_order_older_packet_does_not_expire_flow():
    tr, evs, out = run([pkt("UDP", ts=10), pkt("UDP", ts=2)])
    assert out == [] and evs[0].flow_id == evs[1].flow_id


def test_other_flows_not_touched_by_lazy_expiry():
    other = pkt("UDP", ts=0, src_port=50001)
    tr, evs, out = run([pkt("UDP", ts=0), other, pkt("UDP", ts=9)])
    assert len(out) == 1 and len(tr.table) == 2


def test_default_timeouts_apply_when_flow_section_missing():
    _, _, out = run([pkt("UDP", ts=0), pkt("UDP", ts=61)], cfg={})
    assert len(out) == 1
    _, _, out = run([pkt("UDP", ts=0), pkt("UDP", ts=59)], cfg={})
    assert out == []


def test_flow_section_wrong_type_does_not_crash():
    _, evs, out = run([pkt("UDP", ts=0), pkt("UDP", ts=61)], cfg={"flow": "oops"})
    assert len(out) == 1 and evs[1].flow_id is not None


def test_failing_export_callback_still_creates_new_flow():
    def boom(_):
        raise RuntimeError("x")

    tr, evs, out = run([pkt("UDP", ts=0), pkt("UDP", ts=9)], cb=boom)
    assert evs[1].flow_id != evs[0].flow_id and len(tr.table) == 1


def test_invalid_event_does_not_trigger_expiry():
    bad = pkt("UDP", ts=50, preprocess_status="invalid")
    tr, evs, out = run([pkt("UDP", ts=0), bad])
    assert out == [] and evs[1].flow_id is None