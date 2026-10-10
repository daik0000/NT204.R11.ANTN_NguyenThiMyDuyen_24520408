import pytest
from types import SimpleNamespace as NS

from src.flow.tracker import FlowTracker

A, B = ("10.0.0.1", 40000), ("10.0.0.2", 80)


def pkt(flags, frm="C", ts=100.0, proto="TCP", **kw):
    src, dst = (A, B) if frm == "C" else (B, A)
    d = dict(
        timestamp=ts, transport_protocol=proto,
        src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
        transport_fields={"flags": flags}, raw_length=60,
        payload=b"", preprocess_status="valid", app_protocol=None,
    )
    d.update(kw)
    return NS(**d)


def run(packets, cfg=None, on_export=None):
    exported = []

    def cb(f):
        exported.append(f)
        if on_export:
            on_export(f)

    tr = FlowTracker(cfg or {}, on_export=cb)
    events = [tr.update(p) for p in packets]
    return tr, events, exported


def CLOSE(t0=100.0):
    return [
        pkt(["SYN"], "C", t0),
        pkt(["SYN", "ACK"], "S", t0 + 0.1),
        pkt(["ACK"], "C", t0 + 0.2),
        pkt(["FIN", "ACK"], "C", t0 + 1.0),
        pkt(["FIN", "ACK"], "S", t0 + 1.1),
        pkt(["ACK"], "C", t0 + 1.2),
    ]


def RESET(t0=100.0):
    return [
        pkt(["SYN"], "C", t0),
        pkt(["SYN", "ACK"], "S", t0 + 0.1),
        pkt(["ACK"], "C", t0 + 0.2),
        pkt(["RST"], "S", t0 + 0.3),
    ]


@pytest.mark.parametrize("seq", [CLOSE, RESET])
def test_pure_syn_after_terminated_flow_creates_new_flow(seq):
    tr, ev, out = run(seq() + [pkt(["SYN"], "C", 130.0)])
    assert len(out) == 1 and out[0].close_reason == "port_reuse"
    new = ev[-1]
    assert new.flow_id != ev[0].flow_id
    assert new.flow_state == "HANDSHAKE"
    flow = tr.table.get(next(k for k, _ in tr.table.items())).flow
    assert flow.start_time == 130.0
    assert flow.syn_count == 1 and flow.packet_count == 1


def test_old_flow_keeps_final_numbers():
    _, _, out = run(CLOSE() + [pkt(["SYN"], "C", 130.0)])
    old = out[0]
    assert old.state == "CLOSED"
    assert old.packet_count == 6
    assert old.syn_count == 2 and old.fin_count == 2
    assert old.last_seen == pytest.approx(101.2)


def test_old_flow_exported_before_new_exists():
    sizes = []
    tr = None

    def on_export(_):
        sizes.append(len(tr.table))

    tr = FlowTracker({}, on_export=on_export)
    for p in CLOSE() + [pkt(["SYN"], "C", 130.0)]:
        tr.update(p)
    assert sizes == [0]
    assert len(tr.table) == 1


@pytest.mark.parametrize("flags", [
    ["SYN", "ACK"], ["ACK"], ["FIN", "ACK"], ["RST"], ["PSH", "ACK"], [],
])
def test_non_pure_syn_stays_in_terminated_flow(flags):
    tr, ev, out = run(CLOSE() + [pkt(flags, "S", 130.0)])
    assert out == []
    assert ev[-1].flow_id == ev[0].flow_id
    assert len(tr.table) == 1


@pytest.mark.parametrize("prefix", [
    lambda: [pkt(["SYN"], "C", 100.0)],                                   # HANDSHAKE
    lambda: [pkt(["SYN"], "C", 100.0), pkt(["SYN", "ACK"], "S", 100.1),
             pkt(["ACK"], "C", 100.2)],                                   # ESTABLISHED
    lambda: [pkt(["SYN"], "C", 100.0), pkt(["SYN", "ACK"], "S", 100.1),
             pkt(["ACK"], "C", 100.2), pkt(["FIN", "ACK"], "C", 101.0)],  # CLOSING
])
def test_syn_on_live_flow_is_retransmit(prefix):
    tr, ev, out = run(prefix() + [pkt(["SYN"], "C", 102.0)])
    assert out == []
    assert ev[-1].flow_id == ev[0].flow_id
    assert len(tr.table) == 1


def test_other_side_can_open_next_connection():
    tr, ev, out = run(CLOSE() + [pkt(["SYN"], "S", 130.0)])
    assert len(out) == 1 and out[0].close_reason == "port_reuse"
    new = tr.table.get(next(k for k, _ in tr.table.items())).flow
    assert new.endpoint_a == {"ip": B[0], "port": B[1]}


def test_three_back_to_back_connections():
    tr, ev, out = run(CLOSE(100.0) + CLOSE(200.0) + CLOSE(300.0))
    ids = {e.flow_id for e in ev}
    assert len(ids) == 3
    assert [f.close_reason for f in out] == ["port_reuse", "port_reuse"]
    assert len(tr.table) == 1


def test_udp_unaffected():
    pk = [pkt(None, "C", 100.0 + i, proto="UDP", transport_fields={}) for i in range(3)]
    tr, ev, out = run(pk)
    assert out == [] and len({e.flow_id for e in ev}) == 1


def test_failing_export_callback_does_not_block_new_flow():
    def boom(_):
        raise RuntimeError("sink down")

    tr, ev, out = run(CLOSE() + [pkt(["SYN"], "C", 130.0)], on_export=boom)
    assert ev[-1].flow_state == "HANDSHAKE"
    assert ev[-1].flow_id != ev[0].flow_id
    assert len(tr.table) == 1