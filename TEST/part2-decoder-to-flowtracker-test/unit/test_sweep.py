import pytest
from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

C = ("10.0.0.1", 50000)
S = ("10.0.0.2", 80)
BASE = {"udp_idle_timeout_sec": 5, "tcp_idle_timeout_sec": 5,
        "tcp_handshake_timeout_sec": 3, "tcp_closed_linger_sec": 2}


def cfg(**kw):
    return {"flow": {**BASE, **kw}}


def pkt(proto="UDP", flags=None, frm="C", ts=0.0, sp=50000, **kw):
    a, b = ((C[0], sp), S) if frm == "C" else (S, (C[0], sp))
    d = dict(packet_id=1, timestamp=100.0 + ts, src_ip=a[0], src_port=a[1],
             dst_ip=b[0], dst_port=b[1], network_protocol="IPv4",
             transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": flags} if proto == "TCP" else {})
    d.update(kw)
    return IDSEvent(**d)


def mk(config, cb=None):
    out = []

    def on_export(f):
        out.append(f)
        if cb:
            cb(f)

    return FlowTracker(config, on_export=on_export), out


def test_sweep_exports_expired_and_frees_table():
    tr, out = mk(cfg(sweep_interval_sec=1000))
    for sp in (1, 2, 3):
        tr.update(pkt(ts=0, sp=sp))
    assert tr.active_flow_count() == 3
    assert tr.sweep(106.0) == 3
    assert tr.active_flow_count() == 0
    assert [f.close_reason for f in out] == ["idle_timeout"] * 3


def test_sweep_keeps_flows_still_alive():
    tr, out = mk(cfg(sweep_interval_sec=1000))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=4, sp=2))
    assert tr.sweep(106.0) == 1
    assert tr.active_flow_count() == 1 and out[0].endpoint_a["port"] == 1


def test_sweep_close_reason_per_state():
    tr, out = mk(cfg(sweep_interval_sec=1000))
    tr.update(pkt("TCP", ["SYN"], ts=0, sp=1))                                    # HANDSHAKE
    for fl, fr in ((["SYN"], "C"), (["SYN", "ACK"], "S"), (["ACK"], "C")):
        tr.update(pkt("TCP", fl, fr, ts=0, sp=2))                                  # ESTABLISHED
    for fl, fr in ((["SYN"], "C"), (["SYN", "ACK"], "S"), (["ACK"], "C"), (["RST"], "S")):
        tr.update(pkt("TCP", fl, fr, ts=0, sp=3))                                  # RESET
    for fl, fr in ((["SYN"], "C"), (["SYN", "ACK"], "S"), (["ACK"], "C"),
                   (["FIN", "ACK"], "C"), (["FIN", "ACK"], "S")):
        tr.update(pkt("TCP", fl, fr, ts=0, sp=4))                                  # CLOSED
    tr.sweep(120.0)
    got = {f.endpoint_a["port"]: f.close_reason for f in out}
    assert got == {1: "handshake_timeout", 2: "idle_timeout", 3: "tcp_reset", 4: "tcp_closed"}


def test_sweep_closed_flow_waits_for_linger_then_goes():
    tr, out = mk(cfg(sweep_interval_sec=1000))
    for fl, fr in ((["SYN"], "C"), (["SYN", "ACK"], "S"), (["ACK"], "C"), (["RST"], "S")):
        tr.update(pkt("TCP", fl, fr, ts=0))
    assert tr.sweep(101.5) == 0
    assert tr.sweep(102.5) == 1 and out[0].close_reason == "tcp_reset"


def test_sweep_exports_oldest_first_deterministic():
    tr, out = mk(cfg(sweep_interval_sec=1000))
    for sp in (3, 1, 2):
        tr.update(pkt(ts=0, sp=sp))
    tr.sweep(120.0)
    assert [f.endpoint_a["port"] for f in out] == [3, 1, 2]


def test_sweep_without_argument_uses_watermark():
    tr, out = mk(cfg(sweep_interval_sec=1000))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=20, sp=2))
    assert tr.sweep() == 1


@pytest.mark.parametrize("bad", [None, float("nan"), float("inf"), "x"])
def test_sweep_with_invalid_now_falls_back_to_watermark(bad):
    tr, out = mk(cfg(sweep_interval_sec=1000))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=20, sp=2))
    assert tr.sweep(bad) == 1


def test_sweep_on_empty_table():
    tr, _ = mk(cfg())
    assert tr.sweep(500.0) == 0


def test_periodic_sweep_runs_from_update_without_touching_old_flow():
    tr, out = mk(cfg(sweep_interval_sec=2))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=3, sp=2))     # sweep runs, flow 1 idle 3 <= 5: still alive
    assert out == []
    tr.update(pkt(ts=7, sp=2))     # sweep runs, flow 1 idle 7 > 5
    assert [f.endpoint_a["port"] for f in out] == [1]
    assert tr.active_flow_count() == 1


def test_no_sweep_before_interval_elapsed():
    tr, out = mk(cfg(sweep_interval_sec=10))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=7, sp=2))
    assert out == []               # flow 1 is expired but the sweep is not due yet
    tr.update(pkt(ts=10, sp=2))
    assert len(out) == 1


def test_default_sweep_interval_matches_settings_yaml():
    tr, out = mk({"flow": dict(BASE)})          # sweep_interval_sec missing -> default 1.0
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=7, sp=2))
    assert len(out) == 1


@pytest.mark.parametrize("bad", ["x", None, 0, -1, float("nan"), float("inf"), True])
def test_invalid_sweep_interval_uses_default(bad):
    tr, out = mk(cfg(sweep_interval_sec=bad))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=7, sp=2))
    assert len(out) == 1


def test_invalid_event_does_not_trigger_sweep_or_move_clock():
    tr, out = mk(cfg(sweep_interval_sec=1))
    tr.update(pkt(ts=0, sp=1))
    tr.update(pkt(ts=500, sp=2, preprocess_status="invalid"))
    tr.update(pkt(ts=float("inf"), sp=3))
    assert out == [] and tr.clock == 100.0


def test_failing_callback_does_not_stop_remaining_exports():
    calls = []

    def boom(f):
        calls.append(f.endpoint_a["port"])
        raise RuntimeError("x")

    tr, out = mk(cfg(sweep_interval_sec=1000), cb=boom)
    for sp in (1, 2, 3):
        tr.update(pkt(ts=0, sp=sp))
    assert tr.sweep(200.0) == 3 and calls == [1, 2, 3] and tr.active_flow_count() == 0


def test_callback_sees_consistent_table_during_sweep():
    seen, holder = [], {}
    tr, out = mk(cfg(sweep_interval_sec=1000), cb=lambda f: seen.append(holder["tr"].active_flow_count()))
    holder["tr"] = tr
    for sp in (1, 2, 3):
        tr.update(pkt(ts=0, sp=sp))
    tr.sweep(200.0)
    assert seen == [2, 1, 0]


def test_manual_sweep_in_far_future_does_not_stall_periodic_sweeps():
    tr, out = mk(cfg(sweep_interval_sec=1))
    tr.update(pkt(ts=0, sp=1))
    tr.sweep(100000.0)
    tr.update(pkt(ts=1, sp=2))
    tr.update(pkt(ts=8, sp=3))
    assert [f.endpoint_a["port"] for f in out] == [1, 2]


def test_flow_cfg_wrong_type_does_not_crash():
    tr, out = mk({"flow": "oops"})
    tr.update(pkt(ts=0))
    tr.update(pkt(ts=100, sp=2))
    assert len(out) == 1