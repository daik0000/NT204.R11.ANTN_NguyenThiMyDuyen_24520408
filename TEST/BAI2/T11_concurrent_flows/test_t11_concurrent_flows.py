import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent
TCP_HDR, UDP_FRAME = 54, 46      # TCP: 14+20+20 no payload; UDP: 14+20+8+4 ("ping"/"pong")

# flow name -> packet ids (in send order). Interleaved on the wire.
PACKETS_OF = {"F1": [1, 5, 11], "F2": [2, 7, 12], "F3": [3, 8, 13], "F4": [4, 9], "F5": [6, 10]}

# flow name -> expected summary, worked out by hand (see notes.md)
EXPECTED = {
    "F1": dict(proto="TCP", a=("10.0.0.1", 40401), b=("10.0.0.2", 9000), pk=(3, 2, 1), bytes=(162, 108, 54),
               syn=2, ack=2, state="ESTABLISHED", duration=2.5),
    "F2": dict(proto="TCP", a=("10.0.0.1", 40402), b=("10.0.0.2", 9000), pk=(3, 2, 1), bytes=(162, 108, 54),
               syn=2, ack=2, state="ESTABLISHED", duration=2.5),
    "F3": dict(proto="TCP", a=("10.0.0.1", 40401), b=("10.0.0.2", 9001), pk=(3, 2, 1), bytes=(162, 108, 54),
               syn=2, ack=2, state="ESTABLISHED", duration=2.5),
    "F4": dict(proto="TCP", a=("10.0.0.3", 40401), b=("10.0.0.4", 9000), pk=(2, 1, 1), bytes=(108, 54, 54),
               syn=2, ack=1, state="HANDSHAKE", duration=1.25),
    "F5": dict(proto="UDP", a=("10.0.0.1", 40401), b=("10.0.0.2", 9000), pk=(2, 1, 1), bytes=(92, 46, 46),
               syn=0, ack=0, state="ACTIVE", duration=1.0),
}


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}, {f["flow_id"]: f for f in flows}


def test_five_connections_five_flows(result):
    events, flows = result
    assert sorted(events) == list(range(1, 14))
    assert len(flows) == 5
    ids = {name: {events[p]["flow_id"] for p in pids} for name, pids in PACKETS_OF.items()}
    assert all(len(v) == 1 for v in ids.values())                     # no flow is split
    assert len({next(iter(v)) for v in ids.values()}) == 5            # no two flows are merged


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_flow_summary(result, name):
    events, flows = result
    exp = EXPECTED[name]
    f = flows[events[PACKETS_OF[name][0]]["flow_id"]]
    assert f["protocol"] == exp["proto"]
    assert (f["endpoint_a"]["ip"], f["endpoint_a"]["port"]) == exp["a"]      # first sender is endpoint_a
    assert (f["endpoint_b"]["ip"], f["endpoint_b"]["port"]) == exp["b"]
    assert (f["packet_count"], f["fwd_packet_count"], f["bwd_packet_count"]) == exp["pk"]
    assert (f["byte_count"], f["fwd_byte_count"], f["bwd_byte_count"]) == exp["bytes"]
    assert (f["syn_count"], f["ack_count"], f["fin_count"], f["rst_count"]) == (exp["syn"], exp["ack"], 0, 0)
    assert f["state"] == exp["state"] and f["duration"] == exp["duration"]
    assert f["close_reason"] == "flush" and f["midstream"] is False


def test_tcp_and_udp_with_same_endpoints_are_different_flows(result):
    events, _ = result
    assert events[1]["flow_id"] != events[6]["flow_id"]                # F1 (TCP) vs F5 (UDP)
    assert events[6]["flow_id"] == events[10]["flow_id"]


@pytest.mark.parametrize("pid,direction", [(1, "forward"), (5, "backward"), (6, "forward"), (10, "backward"),
                                           (9, "backward"), (8, "backward"), (13, "forward")])
def test_direction_follows_each_flows_own_first_sender(result, pid, direction):
    assert result[0][pid]["direction"] == direction


def test_raw_length_per_packet(result):
    events, _ = result
    for pid, e in events.items():
        assert e["raw_length"] == (UDP_FRAME if pid in (6, 10) else TCP_HDR)