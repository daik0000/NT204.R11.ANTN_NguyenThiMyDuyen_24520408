import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent
HDR = 54                      # 14 (Ethernet) + 20 (IP) + 20 (TCP)
REQ_LEN, RESP_LEN = 47, 43    # application payload sizes, counted by hand

# packet_id -> (direction, flow_state, raw_length), worked out by hand
EXPECTED = {
    1: ("forward",  "HANDSHAKE",   HDR),
    2: ("backward", "HANDSHAKE",   HDR),
    3: ("forward",  "ESTABLISHED", HDR),
    4: ("forward",  "ESTABLISHED", HDR + REQ_LEN),
    5: ("backward", "ESTABLISHED", HDR + RESP_LEN),
    6: ("forward",  "ESTABLISHED", HDR),
    7: ("forward",  "ESTABLISHED", HDR + RESP_LEN),   # first packet of flow B is sent by the server
    8: ("backward", "ESTABLISHED", HDR),
}


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}, flows


def _flow(flows, port):
    return next(f for f in flows if port in (f["endpoint_a"]["port"], f["endpoint_b"]["port"])
                and f["endpoint_a"]["port"] != f["endpoint_b"]["port"] and port != 80)


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_direction_state_and_length_per_packet(result, pid):
    events, _ = result
    e = events[pid]
    assert (e["direction"], e["flow_state"], e["raw_length"]) == EXPECTED[pid]


def test_both_directions_share_one_flow_id(result):
    events, flows = result
    assert len(flows) == 2
    assert len({events[p]["flow_id"] for p in range(1, 7)}) == 1
    assert len({events[p]["flow_id"] for p in (7, 8)}) == 1
    assert events[1]["flow_id"] != events[7]["flow_id"]


def test_http_request_and_response_are_parsed(result):
    events, _ = result
    assert events[4]["app_protocol"] == "HTTP" and events[4]["app_fields"]["type"] == "request"
    assert events[5]["app_protocol"] == "HTTP" and events[5]["app_fields"]["type"] == "response"
    assert events[7]["app_protocol"] == "HTTP" and events[7]["app_fields"]["type"] == "response"


def test_flow_a_full_connection(result):
    _, flows = result
    f = _flow(flows, 40201)
    assert f["endpoint_a"] == {"ip": "10.0.0.1", "port": 40201}      # client sent first
    assert f["endpoint_b"] == {"ip": "10.0.0.2", "port": 80}
    assert (f["packet_count"], f["fwd_packet_count"], f["bwd_packet_count"]) == (6, 4, 2)
    assert f["fwd_byte_count"] == 3 * HDR + (HDR + REQ_LEN) == 263
    assert f["bwd_byte_count"] == HDR + (HDR + RESP_LEN) == 151
    assert f["byte_count"] == 414
    assert f["payload_byte_count"] == REQ_LEN + RESP_LEN == 90
    assert (f["syn_count"], f["ack_count"], f["fin_count"], f["rst_count"]) == (2, 5, 0, 0)
    assert f["application_protocol"] == "HTTP"
    assert f["state"] == "ESTABLISHED" and f["midstream"] is False
    assert f["duration"] == 5.0 and f["close_reason"] == "flush"


def test_flow_b_starts_with_server_packet(result):
    _, flows = result
    f = _flow(flows, 40202)
    assert f["endpoint_a"] == {"ip": "10.0.0.2", "port": 80}         # first sender becomes endpoint_a
    assert f["endpoint_b"] == {"ip": "10.0.0.1", "port": 40202}
    assert (f["packet_count"], f["fwd_packet_count"], f["bwd_packet_count"]) == (2, 1, 1)
    assert f["fwd_byte_count"] == HDR + RESP_LEN == 97
    assert f["bwd_byte_count"] == HDR == 54
    assert f["byte_count"] == 151 and f["payload_byte_count"] == RESP_LEN
    assert (f["syn_count"], f["ack_count"]) == (0, 2)
    assert f["application_protocol"] == "HTTP"
    assert f["state"] == "ESTABLISHED" and f["midstream"] is True
    assert f["duration"] == 1.0