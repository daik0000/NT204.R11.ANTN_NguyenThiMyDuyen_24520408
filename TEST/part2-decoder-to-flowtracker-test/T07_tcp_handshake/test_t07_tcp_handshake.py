import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent
RAW = 54   # 14 (Ethernet) + 20 (IP) + 20 (TCP), no payload, no options

# packet_id -> (flow_state, direction), worked out by hand from the TCP state machine
EXPECTED = {
    1: ("HANDSHAKE", "forward"),      # first SYN opens the flow
    2: ("HANDSHAKE", "backward"),     # SYN/ACK from the responder keeps HANDSHAKE (synack_seen)
    3: ("ESTABLISHED", "forward"),    # final ACK from the side that did not send SYN/ACK
    4: ("HANDSHAKE", "forward"),
    5: ("HANDSHAKE", "forward"),      # SYN retransmit: ignored, state unchanged
    6: ("HANDSHAKE", "backward"),
    7: ("ESTABLISHED", "forward"),
}


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}, flows


def test_every_packet_produces_a_tcp_event(result):
    events, _ = result
    assert sorted(events) == [1, 2, 3, 4, 5, 6, 7]
    for e in events.values():
        assert e["status"] == "OK" and e["transport_protocol"] == "TCP"
        assert e["raw_length"] == RAW


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_state_and_direction_per_packet(result, pid):
    events, _ = result
    assert (events[pid]["flow_state"], events[pid]["direction"]) == EXPECTED[pid]


def test_two_connections_two_flows(result):
    events, flows = result
    assert len(flows) == 2
    assert len({events[p]["flow_id"] for p in (1, 2, 3)}) == 1
    assert len({events[p]["flow_id"] for p in (4, 5, 6, 7)}) == 1
    assert events[1]["flow_id"] != events[4]["flow_id"]


def _flow(flows, port):
    return next(f for f in flows if f["endpoint_a"]["port"] == port)


@pytest.mark.parametrize("port,exp", [
    (40101, dict(packet_count=3, fwd_packet_count=2, bwd_packet_count=1, syn_count=2, ack_count=2,
                 byte_count=3 * RAW, duration=2.0)),
    (40102, dict(packet_count=4, fwd_packet_count=3, bwd_packet_count=1, syn_count=3, ack_count=2,
                 byte_count=4 * RAW, duration=3.0)),
])
def test_flow_statistics(result, port, exp):
    _, flows = result
    f = _flow(flows, port)
    for k, v in exp.items():
        assert f[k] == v, k
    assert f["fin_count"] == 0 and f["rst_count"] == 0
    assert f["state"] == "ESTABLISHED" and f["midstream"] is False
    assert f["endpoint_a"] == {"ip": "10.0.0.1", "port": port}      # first sender is endpoint_a
    assert f["endpoint_b"] == {"ip": "10.0.0.2", "port": 80}
    assert f["close_reason"] == "flush"                              # still open when the pcap ends