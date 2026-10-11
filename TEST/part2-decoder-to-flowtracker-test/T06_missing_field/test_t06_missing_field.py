import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case, run_events
from src.models.event import IDSEvent

CASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------- half A: TCP packets without payload (input.pcap)
@pytest.fixture(scope="module")
def pcap_events():
    evs, _flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}


@pytest.mark.parametrize("pid,flags", [(1, ["SYN"]), (2, ["ACK"])])
def test_tcp_packet_without_payload_gets_consistent_empty_values(pcap_events, pid, flags):
    e = pcap_events[pid]
    assert e["status"] == "OK" and e["error_info"] is None
    assert e["transport_fields"]["flags"] == flags
    assert e["app_fields"] == {} and e["decoded_fields"] == {}      # no application layer: empty dicts, not null
    assert e["reason"] == []
    assert e["preprocess_status"] == "valid"
    assert e["processing_action"] == "defaults_filled"                      # nothing to normalize and nothing to fill


# ---------------------------------------------------------------- half B: synthetic events that miss fields
def _event(pid, **overrides):
    base = dict(packet_id=pid, timestamp=1700000000.0 + pid, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                network_protocol="IPv4")                             # only the REQUIRED fields
    base.update(overrides)
    return IDSEvent(**base)


CASES = {
    "min_tcp":        dict(transport_protocol="TCP", src_port=40001, dst_port=80),
    "min_udp":        dict(transport_protocol="UDP", src_port=5353, dst_port=53),
    "none_containers": dict(transport_protocol="TCP", src_port=40003, dst_port=80, network_fields=None,
                            transport_fields=None, app_fields=None, decoded_fields=None, reason=None),
    "wrong_type_containers": dict(transport_protocol="TCP", src_port=40004, dst_port=80, network_fields="x",
                                  transport_fields="x", app_fields=["x"], decoded_fields=5),
    "http_empty":     dict(transport_protocol="TCP", src_port=40005, dst_port=80, app_protocol="HTTP"),
    "dns_empty":      dict(transport_protocol="UDP", src_port=5353, dst_port=53, app_protocol="DNS"),
    "no_transport":   dict(network_fields={"ip_proto_number": 6}),
    "no_src_port":    dict(transport_protocol="TCP", dst_port=80),
}
IDS = {name: i for i, name in enumerate(CASES, start=1)}


@pytest.fixture(scope="module")
def syn():
    events = [_event(IDS[name], **kw) for name, kw in CASES.items()]
    out, _flows = run_events(events)                                 # default config = config/settings.yaml
    return {name: out[IDS[name] - 1] for name in CASES}


def test_no_event_crashes_and_every_result_is_json_serializable(syn):
    assert len(syn) == len(CASES)
    json.dumps(list(syn.values()))


def test_only_required_fields_tcp_gets_defaults(syn):
    e = syn["min_tcp"]
    assert e["network_fields"] == {} and e["app_fields"] == {} and e["decoded_fields"] == {}
    assert e["transport_fields"] == {"flags": []}                    # TCP always has a flags list
    assert e["reason"] == []
    assert e["app_protocol"] is None and e["detection_method"] is None  # missing scalars stay null
    assert e["preprocess_status"] == "valid"                          # missing OPTIONAL fields never make it invalid
    assert e["processing_action"] == "defaults_filled"


def test_only_required_fields_udp_has_no_flags_key(syn):
    e = syn["min_udp"]
    assert e["transport_fields"] == {}                                # UDP has no flags: the key must NOT exist
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "none"


def test_null_containers_are_replaced_by_empty_ones(syn):
    e = syn["none_containers"]
    assert e["network_fields"] == {} and e["app_fields"] == {} and e["decoded_fields"] == {}
    assert e["transport_fields"] == {"flags": []} and e["reason"] == []
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "defaults_filled"


def test_wrong_type_containers_are_replaced_by_empty_ones(syn):
    e = syn["wrong_type_containers"]
    assert (e["error_info"] or {}).get("layer") != "preprocessor"      # the Preprocessor itself must not blow up
    assert e["network_fields"] == {} and e["app_fields"] == {} and e["decoded_fields"] == {}
    assert e["transport_fields"] == {"flags": []}
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "defaults_filled"


def test_http_without_app_fields_gets_empty_headers(syn):
    e = syn["http_empty"]
    assert e["app_fields"] == {"headers": {}, "header_pairs": []}
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "defaults_filled"


def test_dns_without_app_fields_gets_empty_queries_and_answers(syn):
    e = syn["dns_empty"]
    assert e["app_fields"] == {"queries": [], "answers": []}
    assert e["transport_fields"] == {}
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "defaults_filled"


def test_missing_transport_layer_is_partial_not_invalid(syn):
    e = syn["no_transport"]
    assert e["preprocess_status"] == "partial" and e["reason"] == ["missing_transport"]
    assert e["transport_fields"] == {} and e["transport_protocol"] is None


def test_missing_required_port_is_invalid_for_contrast(syn):
    e = syn["no_src_port"]
    assert e["preprocess_status"] == "invalid" and e["reason"] == ["missing_src_port"]
    assert e["processing_action"] == "flagged"