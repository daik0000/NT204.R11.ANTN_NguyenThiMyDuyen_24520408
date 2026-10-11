import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case, run_events
from src.models.event import IDSEvent

CASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------- half A: events that come from input.pcap
@pytest.fixture(scope="module")
def pcap_events():
    evs, _flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}


def test_pcap_http_header_names_are_lowercased_and_values_normalized(pcap_events):
    h = pcap_events[1]["app_fields"]["headers_normalized"]
    assert h == {"host": "www.example.com", "user-agent": "Test/1.0", "accept-language": "en", "x-tag": "a, b"}


def test_pcap_http_raw_headers_are_untouched(pcap_events):
    assert pcap_events[1]["app_fields"]["header_pairs"] == [
        ["HOST", "WwW.ExAmPlE.CoM"], ["User-AGENT", "Test/1.0"], ["ACCEPT-language", "en"],
        ["X-Tag", "a"], ["x-tag", "b"]]                      # original case, order and the duplicate are kept


def test_pcap_http_path_hex_is_uppercased_but_dot_dot_is_not_collapsed(pcap_events):
    app = pcap_events[1]["app_fields"]
    assert app["path_normalized"] == "/dir%2Fsub/../x%2E"     # path only (query is not part of it)
    assert app["uri"] == "/dir%2fsub/../x%2e?Q=%2f"           # raw URI untouched
    assert pcap_events[1]["processing_action"] == "normalized"


def test_pcap_dns_query_name_is_lowercased_and_trailing_dot_removed(pcap_events):
    app = pcap_events[2]["app_fields"]
    assert app["queries_normalized"][0]["name"] == "www.example.com"
    raw = app["queries"][0]["name"]
    assert raw.lower().rstrip(".") == "www.example.com" and raw != raw.lower()      # raw keeps its mixed case


def test_pcap_dns_response_normalizes_names_and_cname_data_only(pcap_events):
    app = pcap_events[3]["app_fields"]
    norm = {a["type"]: a for a in app["answers_normalized"]}
    assert norm["CNAME"]["name"] == "www.example.com"
    assert norm["CNAME"]["data"] == "edge.cdn-example.net"
    assert norm["A"]["name"] == "edge.cdn-example.net"
    assert norm["A"]["data"] == "192.0.2.7"                  # an address is not a domain: untouched
    raw = {a["type"]: a for a in app["answers"]}
    assert raw["CNAME"]["data"] != raw["CNAME"]["data"].lower()                       # raw keeps its mixed case


def test_pcap_event_level_protocols_are_canonical(pcap_events):
    for e in pcap_events.values():
        assert e["network_protocol"] == "IPv4" and e["transport_protocol"] in ("TCP", "UDP")
        assert e["app_protocol"] in ("HTTP", "DNS")
        assert e["preprocess_status"] == "valid"


def test_pcap_already_clean_request_needs_no_normalization(pcap_events):
    e = pcap_events[4]
    assert e["processing_action"] == "none"
    assert e["app_fields"]["headers_normalized"] == {"host": "example.com", "user-agent": "test"}
    assert e["app_fields"]["path_normalized"] == "/index.html"


# ---------------------------------------------------------------- half B: synthetic events (not possible in a pcap)
def _event(pid, **overrides):
    base = dict(packet_id=pid, timestamp=1700000000.0 + pid, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                network_protocol="IPv4", network_fields={"ttl": 64}, src_port=40000 + pid, dst_port=80,
                transport_protocol="TCP", transport_fields={"flags": ["PSH", "ACK"]}, app_protocol="HTTP",
                raw_length=100, payload_length=60)
    base.update(overrides)
    return IDSEvent(**base)


DIRTY_APP = {
    "type": "request", "method": "get", "uri": "/A%2fb/../c?x=%2f", "host": "WwW.ExAmPlE.CoM:8080",
    "header_pairs": [["HOST", "WwW.ExAmPlE.CoM:8080"], ["CONTENT-type", "text/plain"], ["User-AGENT", "x"]],
}
CLEAN_APP = {
    "type": "request", "method": "GET", "uri": "/index.html", "headers": {"host": "example.com"},
    "header_pairs": [["host", "example.com"]],
}
DNS_APP = {
    "queries": [{"name": "WWW.Example.COM.", "type": "A"}],
    "answers": [
        {"name": "WWW.Example.COM.", "type": "CNAME", "data": "Edge.CDN-Example.NET."},
        {"name": "Example.COM.", "type": "NS", "data": "NS1.Example.COM."},
        {"name": "Example.COM.", "type": "TXT", "data": "KeepTHIS.Case."},
    ],
}


@pytest.fixture(scope="module")
def synthetic():
    events = [
        _event(1, network_protocol="ip", transport_protocol="tcp", app_protocol="Http", src_ip=" 10.0.0.1 ",
               app_fields=copy.deepcopy(DIRTY_APP)),
        _event(2, app_fields=copy.deepcopy(CLEAN_APP)),
        _event(3, transport_protocol="UDP", src_port=5353, dst_port=53, transport_fields={}, app_protocol="DNS",
               app_fields=copy.deepcopy(DNS_APP)),
    ]
    out, _flows = run_events(events)                        # default config = config/settings.yaml
    return {e["packet_id"]: e for e in out}


def test_synthetic_protocol_aliases_and_ip_are_standardized(synthetic):
    e = synthetic[1]
    assert (e["network_protocol"], e["transport_protocol"], e["app_protocol"]) == ("IPv4", "TCP", "HTTP")
    assert e["src_ip"] == "10.0.0.1"                         # surrounding spaces removed
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "normalized"


def test_synthetic_headers_host_and_path(synthetic):
    app = synthetic[1]["app_fields"]
    assert app["headers_normalized"] == {"host": "www.example.com:8080", "content-type": "text/plain", "user-agent": "x"}
    assert app["host_normalized"] == "www.example.com:8080"      # the port is kept
    assert app["path_normalized"] == "/A%2Fb/../c"               # hex uppercased, '/../' kept


def test_synthetic_raw_app_fields_are_not_modified(synthetic):
    app = synthetic[1]["app_fields"]
    for key, value in DIRTY_APP.items():
        assert app[key] == value, key
    dns = synthetic[3]["app_fields"]
    assert dns["queries"] == DNS_APP["queries"] and dns["answers"] == DNS_APP["answers"]


def test_synthetic_dns_cname_and_ns_data_lowercased_txt_untouched(synthetic):
    norm = {a["type"]: a for a in synthetic[3]["app_fields"]["answers_normalized"]}
    assert norm["CNAME"] == {"name": "www.example.com", "type": "CNAME", "data": "edge.cdn-example.net"}
    assert norm["NS"] == {"name": "example.com", "type": "NS", "data": "ns1.example.com"}
    assert norm["TXT"] == {"name": "example.com", "type": "TXT", "data": "KeepTHIS.Case."}   # free text: untouched
    assert synthetic[3]["app_fields"]["queries_normalized"] == [{"name": "www.example.com", "type": "A"}]


def test_synthetic_clean_event_is_left_alone(synthetic):
    e = synthetic[2]
    assert e["preprocess_status"] == "valid" and e["processing_action"] == "none"
    assert e["app_fields"]["path_normalized"] == "/index.html"