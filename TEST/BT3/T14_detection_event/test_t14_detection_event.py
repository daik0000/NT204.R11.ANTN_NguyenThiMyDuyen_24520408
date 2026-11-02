import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from scapy.utils import rdpcap

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_defaults_and_udp"       # evidence of the second run (variants.rules on variants.pcap)
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything ------------------------------------------------------------------------------
# input.pcap: p1 SYN, p2 SYN/ACK, p3 ACK (the flow is ESTABLISHED), p4 the request, all 10.0.0.5:52133 <-> 192.168.1.20:80
# The rule: alert tcp any any -> any 80 (msg:"Directory traversal detected"; flow:to_server,established; content:"../";
#           classtype:web-application-attack; priority:1; sid:100001; rev:1;)
# Only p4 can fire (the earlier packets have no payload). One line in detections.jsonl:
EXPECTED_FIELDS = {
    "sid": 100001,
    "rev": 1,
    "msg": "Directory traversal detected",
    "priority": 1,
    "classtype": "web-application-attack",
    "packet_id": 4,
    "src_ip": "10.0.0.5",
    "src_port": 52133,
    "dst_ip": "192.168.1.20",
    "dst_port": 80,
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "flow_direction": "to_server",
    "matched": [{"keyword": "content", "value": "../", "offset": 5, "length": 3}],     # G E T <space> / = 5 bytes, then "../"
}
# timestamp: the timestamp of packet 4 in the pcap = 1700000000.3 (written with make_pcap.py: T + 0.3), read back with Scapy.
# flow_id: the flow_id of packet 4 in events.jsonl, which is also in flows.jsonl (one flow, 4 packets, ESTABLISHED, closed by the final flush).
FIELD_ORDER = ["sid", "rev", "msg", "priority", "classtype", "timestamp", "packet_id", "src_ip", "src_port", "dst_ip", "dst_port",
               "protocol", "application_protocol", "flow_id", "flow_direction", "matched"]
#
# variants.pcap = the four packets above + p5 DNS query (10.0.0.5:5353 -> 192.168.1.20:53) + p6 DNS response (back):
#   14101 (tcp, no classtype / priority / rev)  p4   rev 1 (default), priority 3 (engine.default_priority), classtype null; flow_direction is to_server even though the
#                                                    rule has no flow option (it is the role of the sender, reported for every detection that has a flow); matched ../ at 5
#   14102 (udp -> 53)                           p5   UDP, application_protocol DNS, matched [header], priority 3, classtype null
#   14103 (udp <> 53; classtype, priority 2, rev 3)  p5 and p6   rev 3, priority 2, classtype misc-activity; p6 is the response: flow_direction to_client
# => 4 detections: (4, 14101) (5, 14102) (5, 14103) (6, 14103)
EXPECTED_VARIANT = [
    (4, 14101, {"rev": 1, "priority": 3, "classtype": None, "protocol": "TCP", "application_protocol": "HTTP",
                "flow_direction": "to_server", "matched": [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]}),
    (5, 14102, {"rev": 1, "priority": 3, "classtype": None, "protocol": "UDP", "application_protocol": "DNS",
                "flow_direction": "to_server", "matched": [{"keyword": "header"}]}),
    (5, 14103, {"rev": 3, "priority": 2, "classtype": "misc-activity", "protocol": "UDP", "application_protocol": "DNS",
                "flow_direction": "to_server", "matched": [{"keyword": "header"}]}),
    (6, 14103, {"rev": 3, "priority": 2, "classtype": "misc-activity", "protocol": "UDP", "application_protocol": "DNS",
                "flow_direction": "to_client", "matched": [{"keyword": "header"}]}),
]


def lines_of(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.fixture(scope="module")
def run():
    return run_case_ids(CASE_DIR, rules=["rules.rules"])


@pytest.fixture(scope="module")
def variant():
    VARIANT_DIR.mkdir(exist_ok=True)
    return run_case_ids(VARIANT_DIR, rules=[CASE_DIR / "variants.rules"], pcap_name="../variants.pcap")


@pytest.fixture(scope="module")
def detection(run):
    (d,) = run[2]                      # exactly one line
    return d


# --- one line, every field ------------------------------------------------------------------------------------------------------------

def test_detections_jsonl_has_exactly_one_line(run):
    assert len(run[2]) == 1
    assert len((CASE_DIR / "detections.jsonl").read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("field", sorted(EXPECTED_FIELDS))
def test_each_field(detection, field):
    assert detection[field] == EXPECTED_FIELDS[field]
    assert type(detection[field]) is type(EXPECTED_FIELDS[field])


def test_the_fields_and_their_order(detection):
    assert list(detection) == FIELD_ORDER


def test_the_types_a_log_reader_can_rely_on(detection):
    assert isinstance(detection["timestamp"], float) and isinstance(detection["flow_id"], str)
    assert isinstance(detection["matched"], list) and len(detection["matched"]) >= 1
    assert all(isinstance(detection[k], int) for k in ("sid", "rev", "priority", "packet_id", "src_port", "dst_port"))


def test_timestamp_is_the_timestamp_of_the_packet_in_the_pcap(detection):
    packets = rdpcap(str(CASE_DIR / "input.pcap"))
    assert float(packets[3].time) == detection["timestamp"] == pytest.approx(1700000000.3, abs=1e-6)


# --- cross-checking the three files -------------------------------------------------------------------------------------------------------

def test_flow_id_equals_the_flow_id_of_the_same_packet_in_events(run, detection):
    events = {e["packet_id"]: e for e in run[0]}
    assert detection["flow_id"] == events[detection["packet_id"]]["flow_id"]
    assert detection["flow_id"] is not None


def test_flow_id_is_present_in_flows_jsonl(run, detection):
    flows = {f["flow_id"]: f for f in run[1]}
    assert detection["flow_id"] in flows
    flow = flows[detection["flow_id"]]
    assert flow["endpoint_a"] == {"ip": detection["src_ip"], "port": detection["src_port"]}
    assert flow["endpoint_b"] == {"ip": detection["dst_ip"], "port": detection["dst_port"]}
    assert (flow["protocol"], flow["packet_count"], flow["state"], flow["close_reason"]) == ("TCP", 4, "ESTABLISHED", "flush")


def test_the_event_of_the_same_packet_agrees_with_the_detection(run, detection):
    event = {e["packet_id"]: e for e in run[0]}[detection["packet_id"]]
    for det_key, ev_key in (("timestamp", "timestamp"), ("src_ip", "src_ip"), ("src_port", "src_port"), ("dst_ip", "dst_ip"),
                            ("dst_port", "dst_port"), ("application_protocol", "app_protocol"), ("flow_id", "flow_id")):
        assert detection[det_key] == event[ev_key], det_key
    assert event["transport_protocol"] == detection["protocol"]
    assert event["flow_state"] == "ESTABLISHED" and event["direction"] == "forward"      # forward = sent by endpoint_a, here also to_server


def test_the_four_events_share_the_one_flow(run):
    assert len(run[1]) == 1 and len({e["flow_id"] for e in run[0]}) == 1 and len(run[0]) == 4


def test_the_rules_report_describes_the_rule(run):
    (row,) = run[3]
    assert (row["status"], row["reason"], row["sid"], row["line"]) == ("valid", None, 100001, 2)
    assert row["text"].startswith('alert tcp any any -> any 80 (msg:"Directory traversal detected"')


# --- variant: defaults and a UDP detection -------------------------------------------------------------------------------------------------

def test_variant_detections(variant):
    assert [(d["packet_id"], d["sid"]) for d in variant[2]] == [(p, s) for p, s, _ in EXPECTED_VARIANT]


@pytest.mark.parametrize("packet, sid, fields", EXPECTED_VARIANT, ids=[f"p{p}-{s}" for p, s, _ in EXPECTED_VARIANT])
def test_variant_fields(variant, packet, sid, fields):
    d = next(d for d in variant[2] if (d["packet_id"], d["sid"]) == (packet, sid))
    for key, value in fields.items():
        assert d[key] == value, key
    assert list(d) == FIELD_ORDER


def test_variant_every_flow_id_is_in_events_and_flows(variant):
    events = {e["packet_id"]: e for e in variant[0]}
    flows = {f["flow_id"] for f in variant[1]}
    for d in variant[2]:
        assert d["flow_id"] == events[d["packet_id"]]["flow_id"] and d["flow_id"] in flows


def test_variant_dns_request_and_response_are_one_flow(variant):
    by_packet = {(d["packet_id"], d["sid"]): d for d in variant[2]}
    assert by_packet[(5, 14103)]["flow_id"] == by_packet[(6, 14103)]["flow_id"]
    assert by_packet[(5, 14103)]["flow_id"] != by_packet[(4, 14101)]["flow_id"]        # not the TCP flow
    assert len(variant[1]) == 2


# --- evidence and reproducibility --------------------------------------------------------------------------------------------------------------

def test_evidence_files_exist_in_both_directories(run, variant):
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    for path in (CASE_DIR / "detections.jsonl", CASE_DIR / "rules_report.jsonl"):
        assert str(ROOT) not in path.read_text(encoding="utf-8")


def test_the_pcaps_are_reproducible():
    spec = importlib.util.spec_from_file_location("t14_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    for name, packets in (("input.pcap", module.PACKETS), ("variants.pcap", module.VARIANT_PACKETS)):
        rebuilt = Path(write_pcap(packets, str(CASE_DIR / "_rebuilt.pcap")))
        try:
            assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / name).read_bytes()).hexdigest()
        finally:
            rebuilt.unlink(missing_ok=True)
