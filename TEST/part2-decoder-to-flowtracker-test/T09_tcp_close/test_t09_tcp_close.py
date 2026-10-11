import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent
HDR = 54   # 14 (Ethernet) + 20 (IP) + 20 (TCP), no payload

F, B = "forward", "backward"
HS, EST, CLG, CLD, RST = "HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET"

# packet_id -> (direction, flow_state), worked out by hand from the TCP state machine
EXPECTED = {
    1: (F, HS), 2: (B, HS), 3: (F, EST),
    4: (F, CLG),            # first FIN (client)
    5: (B, CLG),            # plain ACK of the FIN: not both FINs yet
    6: (B, CLD),            # second FIN (server): both FINs seen -> CLOSED (final ACK not required)
    7: (F, CLD),            # final ACK arrives after CLOSED: state stays CLOSED
    8: (F, HS), 9: (B, HS), 10: (F, EST),
    11: (F, RST),           # RST has the highest priority
    12: (B, RST),           # late ACK: RESET is terminal
    13: (F, HS), 14: (B, HS), 15: (F, EST),
    16: (F, CLG),           # only one FIN
    17: (B, CLG),           # ACK of the FIN: still CLOSING
}

# client port -> expected flow, worked out by hand (every packet is 54 bytes, no payload)
FLOWS = {
    40301: dict(packets=7, fwd=4, bwd=3, syn=2, ack=6, fin=2, rst=0, state=CLD, reason="tcp_closed", duration=6.0),
    40302: dict(packets=5, fwd=3, bwd=2, syn=2, ack=3, fin=0, rst=1, state=RST, reason="tcp_reset", duration=4.0),
    40303: dict(packets=5, fwd=3, bwd=2, syn=2, ack=4, fin=1, rst=0, state=CLG, reason="flush", duration=2.0),
}
FIRST_PACKET = {40301: 1, 40302: 8, 40303: 13}


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}, {f["flow_id"]: f for f in flows}


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_direction_and_state_per_packet(result, pid):
    events, _ = result
    assert (events[pid]["direction"], events[pid]["flow_state"]) == EXPECTED[pid]
    assert events[pid]["raw_length"] == HDR


def test_three_flows_and_late_packets_join_their_flow(result):
    events, flows = result
    assert len(flows) == 3
    assert len({events[p]["flow_id"] for p in range(1, 8)}) == 1       # final ACK (7) is in flow 1
    assert len({events[p]["flow_id"] for p in range(8, 13)}) == 1      # late ACK (12) is in flow 2
    assert len({events[p]["flow_id"] for p in range(13, 18)}) == 1


@pytest.mark.parametrize("port", sorted(FLOWS))
def test_flow_summary(result, port):
    events, flows = result
    exp = FLOWS[port]
    f = flows[events[FIRST_PACKET[port]]["flow_id"]]
    assert f["endpoint_a"] == {"ip": "10.0.0.1", "port": port}
    assert f["endpoint_b"] == {"ip": "10.0.0.2", "port": 80}
    assert f["packet_count"] == exp["packets"]
    assert (f["fwd_packet_count"], f["bwd_packet_count"]) == (exp["fwd"], exp["bwd"])
    assert f["byte_count"] == exp["packets"] * HDR
    assert (f["fwd_byte_count"], f["bwd_byte_count"]) == (exp["fwd"] * HDR, exp["bwd"] * HDR)
    assert (f["syn_count"], f["ack_count"], f["fin_count"], f["rst_count"]) == (
        exp["syn"], exp["ack"], exp["fin"], exp["rst"])
    assert f["state"] == exp["state"] and f["close_reason"] == exp["reason"]
    assert f["duration"] == exp["duration"] and f["midstream"] is False