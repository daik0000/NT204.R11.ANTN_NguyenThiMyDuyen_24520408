import dataclasses

import pytest

from src.flow.tracker import FlowTracker
from src.models.event import IDSEvent

A = ("10.0.0.1", 40000)
B = ("10.0.0.2", 80)


def ev(flags=("SYN",), src=A, dst=B, proto="TCP", ts=100.0, **kw):
    d = dict(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": list(flags)})
    d.update(kw)
    return IDSEvent(**d)


def _state(t):
    """Everything snapshot() must leave untouched."""
    return (
        [k for k, _ in t.table.items()],
        t.active_flow_count(),
        t.clock,
        t.last_sweep,
        [dataclasses.asdict(e.flow) for _, e in t.table.items()],
        [(e.fin_fwd, e.fin_bwd, e.synack_seen, e.synack_dir, e.state_changed_at) for _, e in t.table.items()],
    )


def test_returns_the_flow_of_a_tracked_event():
    t = FlowTracker({})
    first = ev()
    t.update(first)
    flow = t.snapshot(first)
    assert flow is not None and flow.flow_id == first.flow_id and flow.state == "HANDSHAKE"


def test_both_directions_find_the_same_flow():
    t = FlowTracker({})
    t.update(ev(["SYN"]))
    forward = t.snapshot(ev(["ACK"]))
    backward = t.snapshot(ev(["SYN", "ACK"], src=B, dst=A))
    assert forward is backward and forward is not None


def test_unknown_flow_gives_none():
    t = FlowTracker({})
    t.update(ev())
    assert t.snapshot(ev(src=("10.0.0.9", 1234))) is None
    assert FlowTracker({}).snapshot(ev()) is None


def test_exported_flow_gives_none():
    t = FlowTracker({"flow": {"tcp_handshake_timeout_sec": 5}})
    first = ev(ts=100.0)
    t.update(first)
    assert t.snapshot(first) is not None
    t.flush()
    assert t.snapshot(first) is None


@pytest.mark.parametrize("kw", [
    dict(preprocess_status="invalid"),
    dict(timestamp=float("nan")),
    dict(timestamp=None),
    dict(transport_protocol="ICMP"),
    dict(transport_protocol=None),
    dict(src_ip=None),
    dict(dst_port=None),
])
def test_untracked_event_gives_none(kw):
    t = FlowTracker({})
    t.update(ev())
    assert t.snapshot(ev(**kw)) is None


def test_protocol_name_is_case_insensitive_like_update():
    t = FlowTracker({})
    t.update(ev(proto="UDP", flags=()))
    assert t.snapshot(ev(proto="udp", flags=())) is not None


def test_tcp_and_udp_flows_with_same_endpoints_are_distinct():
    t = FlowTracker({})
    t.update(ev(proto="TCP"))
    assert t.snapshot(ev(proto="UDP", flags=())) is None


def test_snapshot_changes_nothing():
    t = FlowTracker({})
    packets = [ev(ts=100.0), ev(["SYN", "ACK"], src=B, dst=A, ts=100.1),
               ev(ts=100.2, src=("10.0.0.3", 5555)), ev(ts=100.3, src=("10.0.0.4", 6666))]
    for p in packets:
        t.update(p)
    before = _state(t)
    for _ in range(3):
        for p in packets:
            t.snapshot(p)
    t.snapshot(ev(ts=9999.0))                      # even a far-future event moves no clock
    assert _state(t) == before


def test_snapshot_twice_keeps_lru_order_and_counts():
    t = FlowTracker({})
    first, second = ev(), ev(src=("10.0.0.3", 5555))
    t.update(first)
    t.update(second)
    order = [k for k, _ in t.table.items()]
    count = t.active_flow_count()
    packets = t.snapshot(first).packet_count
    t.snapshot(first)
    t.snapshot(first)
    assert [k for k, _ in t.table.items()] == order          # first was NOT moved to the end
    assert t.active_flow_count() == count
    assert t.snapshot(first).packet_count == packets


def test_snapshot_does_not_expire_or_export_flows():
    exported = []
    t = FlowTracker({"flow": {"udp_idle_timeout_sec": 1}}, on_export=exported.append)
    first = ev(proto="UDP", flags=(), ts=100.0)
    t.update(first)
    late = ev(proto="UDP", flags=(), ts=5000.0)
    assert t.snapshot(late) is not None
    assert exported == [] and t.active_flow_count() == 1


def test_snapshot_does_not_modify_the_event():
    t = FlowTracker({})
    first = ev()
    t.update(first)
    other = ev(flags=["ACK"])
    snap = dataclasses.asdict(other)
    t.snapshot(other)
    assert dataclasses.asdict(other) == snap and other.flow_id is None


# --- snapshot and update() must agree on what is tracked --------------------------------------------

UNTRACKED = [
    dict(preprocess_status="invalid"),
    dict(timestamp=float("nan")),
    dict(timestamp=float("inf")),
    dict(timestamp=None),
    dict(timestamp=True),
    dict(timestamp="100.0"),
    dict(transport_protocol="ICMP"),
    dict(transport_protocol=None),
    dict(src_ip=None),
    dict(dst_ip=None),
    dict(src_port=None),
    dict(dst_port=None),
]


@pytest.mark.parametrize("kw", UNTRACKED, ids=lambda kw: "-".join(f"{k}={v!r}" for k, v in kw.items()))
def test_untracked_by_update_means_none_from_snapshot(kw):
    t = FlowTracker({})
    event = ev(**kw)
    t.update(event)
    assert t.active_flow_count() == 0          # update() did not track it ...
    assert event.flow_id is None
    assert t.snapshot(event) is None           # ... and snapshot() agrees


def test_tracked_by_update_means_the_same_flow_from_snapshot():
    t = FlowTracker({})
    event = ev()
    t.update(event)
    assert t.active_flow_count() == 1
    assert t.snapshot(event).flow_id == event.flow_id


# --- call order: snapshot must come after update() of the same event -------------------------------------

def test_snapshot_before_update_misses_the_first_packet():
    t = FlowTracker({})
    event = ev()
    assert t.snapshot(event) is None           # no flow yet: the wrong order
    t.update(event)
    assert t.snapshot(event).flow_id == event.flow_id


def test_snapshot_after_update_reports_the_state_after_this_packet():
    t = FlowTracker({})
    packets = [ev(["SYN"], ts=100.0), ev(["SYN", "ACK"], src=B, dst=A, ts=100.1), ev(["ACK"], ts=100.2)]
    states = []
    for p in packets:
        t.update(p)
        states.append(t.snapshot(p).state)
    assert states == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]     # the final ACK already counts


def test_snapshot_after_port_reuse_returns_the_new_flow():
    t = FlowTracker({})
    old = ev(["SYN"], ts=100.0)
    t.update(old)
    t.update(ev(["RST"], src=B, dst=A, ts=101.0))
    assert t.snapshot(old).state == "RESET"
    reuse = ev(["SYN"], ts=102.0)
    t.update(reuse)                              # pure SYN on a RESET flow: old flow exported
    assert reuse.flow_id != old.flow_id
    snap = t.snapshot(reuse)
    assert snap.flow_id == reuse.flow_id and snap.state == "HANDSHAKE"
    assert t.active_flow_count() == 1
