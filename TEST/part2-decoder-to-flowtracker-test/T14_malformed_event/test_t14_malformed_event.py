import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case, run_events
from src.models.event import IDSEvent
from src.preprocessor.preprocessor import preprocess_event
from src.utils.config import load_config

CASE_DIR = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CFG = ROOT / "config" / "settings.yaml"


# ================================================= half A: broken packets from input.pcap, three policy settings
def _run(variant, config_path):
    """Run main.py on input.pcap and keep this variant's output as separate evidence files."""
    events, flows = run_case(CASE_DIR, config_path=config_path)
    for name in ("events", "flows"):
        shutil.copy(CASE_DIR / f"{name}.jsonl", CASE_DIR / f"{name}_{variant}.jsonl")
    return events, flows


@pytest.fixture(scope="module")
def flag_run():      # invalid_policy: flag, unsupported_policy: mark (the defaults)
    return _run("flag", DEFAULT_CFG)


@pytest.fixture(scope="module")
def drop_run():      # settings_drop.yaml: invalid_policy: drop
    return _run("drop", CASE_DIR / "settings_drop.yaml")


@pytest.fixture(scope="module")
def skip_run():      # settings_skip.yaml: unsupported_policy: skip
    return _run("skip", CASE_DIR / "settings_skip.yaml")


def _by_id(events):
    return {e["packet_id"]: e for e in events}


def test_policy_files_set_only_the_intended_policy():
    drop = load_config(str(CASE_DIR / "settings_drop.yaml"))["preprocessor"]
    skip = load_config(str(CASE_DIR / "settings_skip.yaml"))["preprocessor"]
    assert drop["invalid_policy"] == "drop" and drop["unsupported_policy"] == "mark"
    assert skip["invalid_policy"] == "flag" and skip["unsupported_policy"] == "skip"


@pytest.mark.parametrize("pid", [1, 4])
def test_truncated_packets_are_invalid_and_flagged(flag_run, pid):
    e = _by_id(flag_run[0])[pid]
    assert e["status"] == "MALFORMED" and e["error_info"]["layer"]
    assert e["preprocess_status"] == "invalid" and e["processing_action"] == "flagged"
    assert e["reason"] == [f"malformed_{e['error_info']['layer']}"]
    assert e["flow_id"] is None and e["direction"] is None and e["flow_state"] is None


def test_icmp_is_partial_and_flagged(flag_run):
    e = _by_id(flag_run[0])[2]
    assert e["preprocess_status"] == "partial" and e["processing_action"] == "flagged"
    assert e["reason"] == ["unsupported_transport:ICMP"]
    assert e["flow_id"] is None


def test_arp_is_partial_and_flagged(flag_run):
    e = _by_id(flag_run[0])[3]
    assert e["status"] == "UNKNOWN"
    assert e["preprocess_status"] == "partial" and e["processing_action"] == "flagged"
    assert e["reason"] == ["unsupported_network"]
    assert e["flow_id"] is None


def test_valid_packet_at_the_end_still_creates_a_flow(flag_run):
    events, flows = flag_run
    e = _by_id(events)[5]
    assert e["preprocess_status"] == "valid" and e["flow_state"] == "HANDSHAKE" and e["flow_id"]
    assert len(flows) == 1 and flows[0]["flow_id"] == e["flow_id"]      # the broken packets left no junk flow
    assert flows[0]["packet_count"] == 1 and flows[0]["byte_count"] == 54


def test_flag_policy_logs_every_packet(flag_run):
    assert sorted(_by_id(flag_run[0])) == [1, 2, 3, 4, 5]


def test_drop_policy_removes_only_the_invalid_packets_from_the_log(drop_run):
    events, flows = drop_run
    assert sorted(_by_id(events)) == [2, 3, 5]                           # 1 and 4 were dropped: no log line
    assert _by_id(events)[2]["processing_action"] == "flagged"           # unsupported_policy is independent
    assert len(flows) == 1


def test_skip_policy_removes_only_unsupported_packets_from_the_log(skip_run):
    events, flows = skip_run
    assert sorted(_by_id(events)) == [1, 4, 5]                           # ICMP (2) and ARP (3) were skipped
    assert _by_id(events)[1]["processing_action"] == "flagged"
    assert len(flows) == 1


# ================================================= half B: synthetic events that cannot come from a pcap
def _event(pid, **overrides):
    base = dict(packet_id=pid, timestamp=1700000000.0 + pid, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                network_protocol="IPv4", transport_protocol="TCP", src_port=40000 + pid, dst_port=80,
                transport_fields={"flags": ["SYN"]})
    base.update(overrides)
    return IDSEvent(**base)


BAD = {   # name -> (event overrides, expected reason)
    "bad_port":   (dict(src_port=70000), ["invalid_src_port"]),
    "nan_time":   (dict(timestamp=float("nan")), ["invalid_timestamp"]),
    "no_src_ip":  (dict(src_ip=None), ["missing_src_ip"]),
}
IDS = {name: i for i, name in enumerate(BAD, start=1)}
GOOD_ID = 4


def _cfg(policy):
    cfg = copy.deepcopy(load_config(str(DEFAULT_CFG)))
    cfg["preprocessor"]["invalid_policy"] = policy
    return cfg


def _run_synthetic(policy):
    events = [_event(IDS[name], **kw) for name, (kw, _r) in BAD.items()] + [_event(GOOD_ID)]
    out, flows = run_events(events, _cfg(policy))
    return {e["packet_id"]: e for e in out}, flows


@pytest.mark.parametrize("policy,action", [("flag", "flagged"), ("drop", "dropped")])
@pytest.mark.parametrize("name", sorted(BAD))
def test_bad_event_is_invalid_with_the_right_reason(name, policy, action):
    out, _ = _run_synthetic(policy)
    e = out[IDS[name]]
    assert e["preprocess_status"] == "invalid" and e["processing_action"] == action
    assert e["reason"] == BAD[name][1]
    assert e["flow_id"] is None                                          # no junk flow for an invalid event


@pytest.mark.parametrize("policy", ["flag", "drop"])
def test_good_event_after_bad_ones_still_creates_a_flow(policy):
    out, flows = _run_synthetic(policy)
    assert out[GOOD_ID]["preprocess_status"] == "valid" and out[GOOD_ID]["flow_id"]
    assert len(flows) == 1 and flows[0]["endpoint_a"]["port"] == 40000 + GOOD_ID


def test_broken_config_gives_a_fail_safe_verdict():
    e = preprocess_event(_event(9), {"flow": {}})                        # config without the "preprocessor" section
    assert e.preprocess_status == "invalid" and e.processing_action == "flagged"
    assert e.error_info["layer"] == "preprocessor"
    json.dumps(e.reason)