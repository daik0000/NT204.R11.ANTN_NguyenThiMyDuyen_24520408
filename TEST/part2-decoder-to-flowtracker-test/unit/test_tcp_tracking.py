import pytest

from src.models.event import IDSEvent
from src.flow.tracker import FlowTracker

C = ("10.0.0.1", 40000)   # client
S = ("10.0.0.2", 80)      # server


def pkt(flags, frm="C", ts=0.0, **kw):
    src, dst = (C, S) if frm == "C" else (S, C)
    d = dict(packet_id=1, timestamp=100.0 + ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol="TCP", raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": flags})
    d.update(kw)
    return IDSEvent(**d)


def run(packets, cfg=None):
    t = FlowTracker(cfg or {})
    return t, [t.update(p) for p in packets]


def flow_of(t):
    return t.table.items()[0][1].flow


def test_t07_handshake_states_directions_and_counters():
    t, evs = run([pkt(["SYN"], "C", 0.00), pkt(["SYN", "ACK"], "S", 0.01), pkt(["ACK"], "C", 0.02)])
    assert [e.flow_state for e in evs] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]
    assert [e.direction for e in evs] == ["forward", "backward", "forward"]
    f = flow_of(t)
    assert (f.state, f.midstream, f.syn_count, f.ack_count) == ("ESTABLISHED", False, 2, 2)
    assert len({e.flow_id for e in evs}) == 1


def test_t07_variant_syn_retransmit_still_ends_established_in_one_flow():
    t, evs = run([pkt(["SYN"], "C", 0), pkt(["SYN"], "C", 1), pkt(["SYN", "ACK"], "S", 1.01), pkt(["ACK"], "C", 1.02)])
    assert [e.flow_state for e in evs] == ["HANDSHAKE"] * 3 + ["ESTABLISHED"]
    assert len(t.table) == 1 and flow_of(t).syn_count == 3


def test_t09_normal_close_ends_closed_and_late_ack_stays_in_the_flow():
    t, evs = run([pkt(["ACK"], "C", 0), pkt(["FIN", "ACK"], "C", 1), pkt(["ACK"], "S", 1.1),
                  pkt(["FIN", "ACK"], "S", 1.2), pkt(["ACK"], "C", 1.3)])
    assert [e.flow_state for e in evs] == ["ESTABLISHED", "CLOSING", "CLOSING", "CLOSED", "CLOSED"]
    f = flow_of(t)
    assert (f.state, f.packet_count, f.fin_count) == ("CLOSED", 5, 2)


def test_t09_reset_is_terminal_and_half_close_stays_closing():
    t, evs = run([pkt(["ACK"], "C", 0), pkt(["RST"], "S", 1), pkt(["ACK"], "C", 2), pkt(["SYN"], "C", 3)])
    assert [e.flow_state for e in evs] == ["ESTABLISHED", "RESET", "RESET", "RESET"]
    assert flow_of(t).rst_count == 1
    _, evs = run([pkt(["ACK"], "C", 0), pkt(["FIN", "ACK"], "C", 1), pkt(["ACK"], "S", 1.1)])
    assert evs[-1].flow_state == "CLOSING"


def test_scan_shapes():
    assert run([pkt(["SYN"], "C"), pkt(["RST", "ACK"], "S", 0.01)])[1][-1].flow_state == "RESET"
    assert run([pkt(["SYN"], "C"), pkt(["SYN", "ACK"], "S", 0.01), pkt(["RST"], "C", 0.02)])[1][-1].flow_state == "RESET"
    assert run([pkt(["SYN"], "C")])[1][-1].flow_state == "HANDSHAKE"


def test_close_requires_final_ack_is_read_from_the_flow_config_section():
    def seq():
        return [pkt(["ACK"], "C", 0), pkt(["FIN", "ACK"], "C", 1), pkt(["FIN", "ACK"], "S", 1.1), pkt(["ACK"], "C", 1.2)]

    assert [e.flow_state for e in run(seq())[1]] == ["ESTABLISHED", "CLOSING", "CLOSED", "CLOSED"]
    cfg = {"flow": {"tcp_close_requires_final_ack": True}}
    assert [e.flow_state for e in run(seq(), cfg)[1]] == ["ESTABLISHED", "CLOSING", "CLOSING", "CLOSED"]


def test_capture_starting_at_syn_ack_becomes_established_and_midstream():
    t, evs = run([pkt(["SYN", "ACK"], "S", 0), pkt(["ACK"], "C", 0.01)])
    assert [e.flow_state for e in evs] == ["HANDSHAKE", "ESTABLISHED"]
    assert flow_of(t).midstream is True


def test_capture_starting_midstream_is_established_and_flagged():
    t, evs = run([pkt(["PSH", "ACK"], "C")])
    assert evs[0].flow_state == "ESTABLISHED" and flow_of(t).midstream is True


def test_internal_entry_state_is_synchronised():
    t, _ = run([pkt(["ACK"], "C", 0), pkt(["FIN", "ACK"], "C", 5)])
    e = t.table.items()[0][1]
    assert e.fin_fwd is True and e.fin_bwd is False and e.state_changed_at == 105.0
    t, _ = run([pkt(["SYN"], "C", 0), pkt(["SYN", "ACK"], "S", 1)])
    entry = t.table.items()[0][1]
    assert entry.synack_seen is True and entry.synack_dir == "backward"


def test_state_changed_at_moves_only_on_a_real_transition():
    t, _ = run([pkt(["ACK"], "C", 0), pkt(["ACK"], "S", 7)])
    assert t.table.items()[0][1].state_changed_at == 100.0


def test_udp_flow_state_is_active_and_untouched():
    t, evs = run([pkt(None, "C", transport_protocol="UDP", transport_fields={}),
                  pkt(None, "S", 1, transport_protocol="UDP", transport_fields={})])
    assert [e.flow_state for e in evs] == ["ACTIVE", "ACTIVE"]


def test_untrackable_event_has_no_flow_state():
    assert run([pkt(["SYN"], preprocess_status="invalid")])[1][0].flow_state is None


@pytest.mark.parametrize("flags", [None, [], "SYN", 5])
def test_missing_flags_do_not_crash(flags):
    _, evs = run([pkt(flags)])
    assert evs[0].error_info is None and evs[0].flow_state == "ESTABLISHED"