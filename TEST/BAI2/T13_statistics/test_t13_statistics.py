import sys
from pathlib import Path

import pytest
from scapy.all import TCP, rdpcap

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent

# Read back from input.pcap with Scapy: frame length and application data length of every packet.
PCAP = rdpcap(str(CASE_DIR / "input.pcap"))
FRAMES = [len(p) for p in PCAP]
DATA = [len(p[TCP].payload) for p in PCAP]
# Hand calculation: frame = 14 + 20 + 20 + data
assert FRAMES == [54, 54, 54, 64, 74, 84, 94, 54, 54]
assert DATA == [0, 0, 0, 10, 20, 30, 40, 0, 0]

F, B = "forward", "backward"
# packet_id -> (direction, flow_state), worked out by hand from the TCP state machine
EXPECTED = {
    1: (F, "HANDSHAKE"), 2: (B, "HANDSHAKE"), 3: (F, "ESTABLISHED"),
    4: (F, "ESTABLISHED"), 5: (B, "ESTABLISHED"), 6: (F, "ESTABLISHED"), 7: (B, "ESTABLISHED"),
    8: (F, "CLOSING"), 9: (B, "CLOSED"),
}
FWD_IDS, BWD_IDS = [1, 3, 4, 6, 8], [2, 5, 7, 9]


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}, flows


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_packet_direction_state_and_length(result, pid):
    e = result[0][pid]
    assert (e["direction"], e["flow_state"]) == EXPECTED[pid]
    assert e["raw_length"] == FRAMES[pid - 1]
    assert e["payload_length"] == 20 + DATA[pid - 1]       # event payload_length includes the 20-byte TCP header


def test_exactly_one_flow(result):
    events, flows = result
    assert len(flows) == 1
    assert len({e["flow_id"] for e in events.values()}) == 1


def test_flow_counters_match_the_hand_table(result):
    _, flows = result
    f = flows[0]
    assert f["protocol"] == "TCP"
    assert f["endpoint_a"] == {"ip": "10.0.0.1", "port": 40601}
    assert f["endpoint_b"] == {"ip": "10.0.0.2", "port": 9000}
    assert (f["packet_count"], f["fwd_packet_count"], f["bwd_packet_count"]) == (9, 5, 4)
    assert f["byte_count"] == 586
    assert (f["fwd_byte_count"], f["bwd_byte_count"]) == (310, 276)
    assert f["payload_byte_count"] == 100
    assert (f["syn_count"], f["ack_count"], f["fin_count"], f["rst_count"]) == (2, 8, 2, 0)
    assert f["start_time"] == 1700000000.0 and f["last_seen"] == 1700000008.0
    assert f["duration"] == pytest.approx(f["last_seen"] - f["start_time"]) == pytest.approx(8.0)
    assert f["state"] == "CLOSED" and f["close_reason"] == "tcp_closed" and f["midstream"] is False


def test_counters_agree_with_the_pcap_read_back_by_scapy(result):
    _, flows = result
    f = flows[0]
    assert f["byte_count"] == sum(FRAMES)
    assert f["fwd_byte_count"] == sum(FRAMES[i - 1] for i in FWD_IDS)
    assert f["bwd_byte_count"] == sum(FRAMES[i - 1] for i in BWD_IDS)
    assert f["payload_byte_count"] == sum(DATA)            # application data only, handshake/ACK/FIN add 0
    assert f["packet_count"] == len(PCAP)