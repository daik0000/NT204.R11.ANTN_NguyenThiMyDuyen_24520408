import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case
from src.flow.tracker import FlowTracker
from src.utils.config import load_config

CASE_DIR = Path(__file__).resolve().parent
SETTINGS = CASE_DIR / "settings.yaml"
UDP, TCP_HDR = 44, 54      # UDP: 14+20+8+2 ("hi"); TCP without payload: 14+20+20

# flow name -> (packet ids, expected summary), worked out by hand (see notes.md)
PACKETS_OF = {"U": [1, 4], "E": [2, 5, 6], "H": [3], "U2": [7], "X": [8]}
EXPECTED = {
    "U":  dict(proto="UDP", a=("10.0.0.1", 50001), pk=(2, 1, 1), byte=88, state="ACTIVE", dur=1.0, reason="idle_timeout"),
    "E":  dict(proto="TCP", a=("10.0.0.1", 40501), pk=(3, 2, 1), byte=162, state="ESTABLISHED", dur=1.5, reason="idle_timeout"),
    "H":  dict(proto="TCP", a=("10.0.0.1", 40502), pk=(1, 1, 0), byte=54, state="HANDSHAKE", dur=0.0, reason="handshake_timeout"),
    "U2": dict(proto="UDP", a=("10.0.0.1", 50001), pk=(1, 1, 0), byte=44, state="ACTIVE", dur=0.0, reason="idle_timeout"),
    "X":  dict(proto="TCP", a=("10.0.0.9", 50009), pk=(1, 1, 0), byte=54, state="HANDSHAKE", dur=0.0, reason="flush"),
}


@pytest.fixture(scope="module")
def result():
    evs, flows = run_case(CASE_DIR, config_path=SETTINGS)
    return {e["packet_id"]: e for e in evs}, flows


def test_settings_file_overrides_timeouts():
    flow_cfg = load_config(SETTINGS)["flow"]
    assert (flow_cfg["udp_idle_timeout_sec"], flow_cfg["tcp_idle_timeout_sec"]) == (5, 5)
    assert (flow_cfg["tcp_handshake_timeout_sec"], flow_cfg["sweep_interval_sec"]) == (3, 1)


def test_expired_flows_are_exported_before_the_flush(result):
    _, flows = result
    assert len(flows) == 5
    assert [f["close_reason"] for f in flows][-1] == "flush"          # only X is still open at the end of the pcap
    assert [f["close_reason"] for f in flows].count("flush") == 1


def test_packet_after_timeout_opens_a_new_flow(result):
    events, _ = result
    assert events[7]["flow_id"] != events[1]["flow_id"]                # same 5-tuple, different flow
    assert events[1]["flow_id"] == events[4]["flow_id"]
    assert events[7]["direction"] == "forward" and events[7]["flow_state"] == "ACTIVE"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_flow_summary(result, name):
    events, flows = result
    exp = EXPECTED[name]
    by_id = {f["flow_id"]: f for f in flows}
    f = by_id[events[PACKETS_OF[name][0]]["flow_id"]]
    assert f["protocol"] == exp["proto"]
    assert (f["endpoint_a"]["ip"], f["endpoint_a"]["port"]) == exp["a"]
    assert (f["packet_count"], f["fwd_packet_count"], f["bwd_packet_count"]) == exp["pk"]
    assert f["byte_count"] == exp["byte"]
    assert f["state"] == exp["state"] and f["duration"] == exp["dur"]
    assert f["close_reason"] == exp["reason"]


def _ev(ts, proto, sip, sport, dip, dport, flags=None, raw=TCP_HDR, payload=b""):
    return SimpleNamespace(timestamp=ts, preprocess_status="valid", transport_protocol=proto, src_ip=sip, src_port=sport,
                           dst_ip=dip, dst_port=dport, transport_fields={"flags": flags} if flags else {},
                           raw_length=raw, payload=payload, app_protocol=None)


def test_active_table_shrinks_when_flows_expire():
    exported = []
    tracker = FlowTracker(load_config(SETTINGS), on_export=exported.append)
    tracker.update(_ev(0.0, "UDP", "10.0.0.1", 50001, "10.0.0.2", 9000, raw=UDP, payload=b"hi"))
    tracker.update(_ev(0.5, "TCP", "10.0.0.1", 40501, "10.0.0.2", 9100, ["SYN"]))
    tracker.update(_ev(0.75, "TCP", "10.0.0.1", 40502, "10.0.0.2", 9200, ["SYN"]))
    assert tracker.active_flow_count() == 3 and exported == []
    tracker.update(_ev(8.0, "UDP", "10.0.0.1", 50001, "10.0.0.2", 9000, raw=UDP, payload=b"hi"))
    # U (lazy), E and H (sweep) are gone; only the new UDP flow remains
    assert tracker.active_flow_count() == 1
    assert sorted((f.endpoint_a["port"], f.close_reason) for f in exported) == [
        (40501, "handshake_timeout"), (40502, "handshake_timeout"), (50001, "idle_timeout")]