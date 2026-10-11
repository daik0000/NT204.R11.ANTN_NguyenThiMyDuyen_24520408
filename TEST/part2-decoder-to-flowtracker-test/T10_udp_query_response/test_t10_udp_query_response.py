import sys
from pathlib import Path

import pytest
from scapy.all import rdpcap

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent
F, B = "forward", "backward"

# Frame lengths read back from input.pcap with Scapy (not taken from the program output).
FRAMES = [len(p) for p in rdpcap(str(CASE_DIR / "input.pcap"))]
# Cross-check by hand: Ethernet 14 + IP 20 + UDP 8 + DNS message.
#   query 1 = 33 DNS bytes -> 75; response 1 = 33 + one A record (17 name + 14) = 64 -> 106
#   query 2 = 12 header + 25 name + 4 = 41 -> 83; response 2 (NXDOMAIN, no answers) = 41 -> 83
assert FRAMES == [75, 106, 83, 83]

# packet_id -> direction
DIRECTION = {1: F, 2: B, 3: F, 4: B}
FLOWS = {   # client port -> (first packet id, packets of the flow)
    53011: (1, (1, 2)),
    53012: (3, (3, 4)),
}


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}, {f["flow_id"]: f for f in flows}


@pytest.mark.parametrize("pid", sorted(DIRECTION))
def test_dns_event_per_packet(result, pid):
    e = result[0][pid]
    assert e["status"] == "OK" and e["error_info"] is None
    assert e["transport_protocol"] == "UDP" and e["app_protocol"] == "DNS"
    assert e["direction"] == DIRECTION[pid] and e["flow_state"] == "ACTIVE"
    assert e["raw_length"] == FRAMES[pid - 1]
    assert "flags" not in e["transport_fields"]          # UDP has no TCP flags


def test_query_and_response_share_one_flow_each(result):
    events, flows = result
    assert len(flows) == 2
    assert events[1]["flow_id"] == events[2]["flow_id"]
    assert events[3]["flow_id"] == events[4]["flow_id"]
    assert events[1]["flow_id"] != events[3]["flow_id"]


@pytest.mark.parametrize("port,exp_duration", [(53011, 0.5), (53012, 0.25)])
def test_udp_flow_summary(result, port, exp_duration):
    events, flows = result
    first, pkts = FLOWS[port]
    f = flows[events[first]["flow_id"]]
    q, r = FRAMES[pkts[0] - 1], FRAMES[pkts[1] - 1]
    assert f["protocol"] == "UDP" and f["application_protocol"] == "DNS"
    assert f["endpoint_a"] == {"ip": "10.0.0.1", "port": port}          # the querier sent first
    assert f["endpoint_b"] == {"ip": "10.0.0.53", "port": 53}
    assert (f["packet_count"], f["fwd_packet_count"], f["bwd_packet_count"]) == (2, 1, 1)
    assert (f["fwd_byte_count"], f["bwd_byte_count"], f["byte_count"]) == (q, r, q + r)
    assert (f["syn_count"], f["ack_count"], f["fin_count"], f["rst_count"]) == (0, 0, 0, 0)
    assert f["state"] == "ACTIVE" and f["midstream"] is False
    assert f["duration"] == exp_duration and f["close_reason"] == "flush"