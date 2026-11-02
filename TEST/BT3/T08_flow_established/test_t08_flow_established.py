import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.capture.pcap_reader import read_pcap
from src.engine.content_matcher import content_fn, match_contents
from src.engine.flow_context import build_flow_context
from src.engine.matcher import match_rule
from src.flow.tracker import FlowTracker
from src.pipeline.pipeline import _parse_packet_layers
from src.utils.config import load_config

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_close_and_reset"
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything -----------------------------------------------------------------------------
# Rules (the TCP ones have the header "tcp any any -> any any", so only the flow / packet / content parts decide):
#   8001 flow:to_server,established; content:"GET"            8002 flow:to_client,established; content:"HTTP/1.1 200"
#   8003 flow:to_server,not_established; flags:S               8004 flow:to_client,not_established; flags:SA
#   8005 flow:to_client,established; content:"GET"   (wrong way round: a GET is never sent to the client)
#   8006 udp any any <> any 53; flow:not_established            ("<>" so that the DNS response passes the header: if it does not fire,
#                                                                the reason is "established", not the header)
# State of the flow AFTER each packet, and the role of the packet's sender (80 and 53 are in cfg["ports"]):
#   p1 SYN (flow 1)        HANDSHAKE   to_server  -> 8003
#   p2 SYN/ACK             HANDSHAKE   to_client  -> 8004
#   p3 ACK, no payload     ESTABLISHED to_server  -> nothing (8001 needs content GET; the payload is empty)
#   p4 GET /               ESTABLISHED to_server  -> 8001   (8005 has the wrong role)
#   p5 HTTP/1.1 200 OK     ESTABLISHED to_client  -> 8002   (8005 passes flow but its content GET is absent)
#   p6 GET / (flow 2, midstream, no handshake)  ESTABLISHED (midstream), role from port 80 = to_server -> 8001
#   p7 HTTP/1.1 200 OK (flow 3, midstream, captured from the SERVER side: endpoint_a = server)
#        direction "forward" but role to_client -> 8002
#   p8 DNS query           no reverse packet yet -> not established, to_server -> 8006
#   p9 DNS response        a reverse packet exists (this one) -> established -> 8006 does NOT fire
DETECTIONS_BY_PACKET = {1: [8003], 2: [8004], 3: [], 4: [8001], 5: [8002], 6: [8001], 7: [8002], 8: [8006], 9: []}
TOTAL_BY_SID = {8001: 2, 8002: 2, 8003: 1, 8004: 1, 8005: 0, 8006: 1}                 # 7 in all
ROLE_BY_PACKET = {1: "to_server", 2: "to_client", 4: "to_server", 5: "to_client", 6: "to_server", 7: "to_client", 8: "to_server"}
# Counters: 5 TCP rules are candidates of each of the 7 TCP packets (35) + the UDP rule for the 2 UDP packets = 37.
#   rejected_flow: p1 4, p2 4, p3 4, p4 4, p5 3, p6 4, p7 3, p8 0, p9 1 = 27   (packet stage: nothing fails)
#   content stage entered: p3 8001 | p4 8001 | p5 8002, 8005 | p6 8001 | p7 8002, 8005 = 7   (3 of them fail: p3 8001, p5 8005, p7 8005)
#   matches: 8003, 8004, 8006 (no content) + 4 with content = 7        37 = 27 + 3 + 7
#
# variants.rules / variants.pcap:  8101 flow:established; flags:FA    8102 flow:not_established; flags:RA    8103 flow:from_client,established; flags:A
#   flow X: p3 ACK ESTABLISHED -> 8103 | p4 FIN/ACK from client: CLOSING (established) -> 8101 | p5 FIN/ACK from server: CLOSED -> 8101
#           p6 late ACK from the client: still CLOSED (established) -> 8103
#   flow Y: p9 ACK -> 8103 | p10 RST/ACK from the server: RESET = not established -> 8102
VARIANT_DETECTIONS = [(3, 8103), (4, 8101), (5, 8101), (6, 8103), (9, 8103), (10, 8102)]
# variant counters: candidates 3 x 10 = 30; rejected_flow 16 (8101: 5, 8102: 5, 8103: 6); rejected_packet 8 (3 + 4 + 1); matches 6


def sid_counts(detections):
    counts = {sid: 0 for sid in TOTAL_BY_SID}
    for d in detections:
        counts[d["sid"]] += 1
    return counts


def engine_line(stderr):
    return [l for l in stderr.splitlines() if "| engine:" in l][-1]


@pytest.fixture(scope="module")
def run():
    stderr = []
    return run_case_ids(CASE_DIR, rules=["rules.rules"], stderr_out=stderr) + (stderr[0],)


@pytest.fixture(scope="module")
def variant():
    VARIANT_DIR.mkdir(exist_ok=True)
    stderr = []
    out = run_case_ids(VARIANT_DIR, rules=[CASE_DIR / "variants.rules"], pcap_name="../variants.pcap", stderr_out=stderr)
    return out + (stderr[0],)


# --- which rule fires on which packet -------------------------------------------------------------------------------------------

def test_detections_per_packet(run):
    per_packet = {pid: [] for pid in DETECTIONS_BY_PACKET}
    for d in run[2]:
        per_packet[d["packet_id"]].append(d["sid"])
    assert per_packet == DETECTIONS_BY_PACKET


def test_totals_per_rule(run):
    assert sid_counts(run[2]) == TOTAL_BY_SID and len(run[2]) == 7


def test_the_wrong_way_round_rule_never_fires(run):
    assert 8005 not in {d["sid"] for d in run[2]}


def test_roles_reported_in_the_detections(run):
    roles = {d["packet_id"]: d["flow_direction"] for d in run[2]}
    assert roles == ROLE_BY_PACKET


def test_packet_7_is_forward_but_to_client(run):
    events = {e["packet_id"]: e for e in run[0]}
    detection = next(d for d in run[2] if d["packet_id"] == 7)
    assert events[7]["direction"] == "forward"                           # endpoint_a of that flow is the server
    assert detection["flow_direction"] == "to_client" and detection["sid"] == 8002
    flows = run[1]
    midstream_server_first = [f for f in flows if f["midstream"] and f["endpoint_a"] == {"ip": "10.0.0.2", "port": 80}]
    assert len(midstream_server_first) == 1


def test_midstream_flows_count_as_established(run):
    events = {e["packet_id"]: e for e in run[0]}
    assert events[6]["flow_state"] == "ESTABLISHED" and events[7]["flow_state"] == "ESTABLISHED"
    assert [f["midstream"] for f in run[1]].count(True) == 2              # flow 2 and flow 3


def test_state_after_each_tcp_packet_of_flow_1(run):
    events = {e["packet_id"]: e for e in run[0]}
    assert [events[p]["flow_state"] for p in (1, 2, 3, 4, 5)] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED", "ESTABLISHED", "ESTABLISHED"]


def test_udp_query_is_not_established_and_the_response_is(run):
    fired = {d["packet_id"] for d in run[2] if d["sid"] == 8006}
    assert fired == {8}


def test_counters(run):
    line = engine_line(run[4])
    assert "events_evaluated=9 " in line and "candidate_rules=37 " in line
    assert "rejected_header=0 " in line and "rejected_flow=27 " in line and "rejected_packet=0 " in line
    assert "content_evaluations=7 " in line and "rejected_content=3 " in line and "matches=7 " in line and "rule_errors=0" in line
    summary = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert "rules(loaded=6, invalid=0, unsupported=0), events_evaluated=9, candidates=37, detections=7" in summary


def test_rules_report_and_flows(run):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", s) for s in (8001, 8002, 8003, 8004, 8005, 8006)]
    assert len(run[0]) == 9 and len(run[1]) == 4


# --- the stage that rejects, packet by packet (real MatchResult) -----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def replay():
    cfg = load_config()
    tracker = FlowTracker(cfg)
    out = {}
    for pid, (ts, raw) in enumerate(read_pcap(str(CASE_DIR / "input.pcap")), start=1):
        event = _parse_packet_layers(ts, raw, pid)
        tracker.update(event)
        out[pid] = (event, build_flow_context(event, tracker.snapshot(event), cfg))
    _, _, rules = run_rules_only(CASE_DIR / "rules.rules")
    return out, {r.sid: r for r in rules}


def test_8005_fails_at_the_flow_stage_not_at_the_header(replay):
    packets, rules = replay
    event, ctx = packets[4]
    result = match_rule(rules[8005], event, ctx, content_fn)
    assert (result.matched, result.failed_stage) == (False, "flow")
    assert match_contents(rules[8005], event.payload) is not None        # "GET" is in the packet: only the role is wrong
    assert ctx.role == "to_server"


def test_8005_on_the_response_passes_the_flow_and_fails_the_content(replay):
    packets, rules = replay
    event, ctx = packets[5]
    result = match_rule(rules[8005], event, ctx, content_fn)
    assert (result.matched, result.failed_stage) == (False, "content")
    assert (ctx.role, ctx.established) == ("to_client", True)


def test_the_dns_response_is_rejected_by_established_not_by_the_header(replay):
    packets, rules = replay
    event, ctx = packets[9]
    result = match_rule(rules[8006], event, ctx, content_fn)
    assert (result.matched, result.failed_stage) == (False, "flow")      # the "<>" header accepted the reply
    assert (ctx.established, ctx.role) == (True, "to_client")
    assert match_rule(rules[8006], *packets[8], content_fn).matched is True


def test_contexts_of_the_midstream_flows(replay):
    packets, _ = replay
    c6, c7 = packets[6][1], packets[7][1]
    assert (c6.role, c6.established, c6.midstream, c6.direction) == ("to_server", True, True, "forward")
    assert (c7.role, c7.established, c7.midstream, c7.direction) == ("to_client", True, True, "forward")   # forward is not to_server


# --- variant: close and reset -----------------------------------------------------------------------------------------------------------------------

def test_variant_detections(variant):
    assert [(d["packet_id"], d["sid"]) for d in variant[2]] == VARIANT_DETECTIONS


def test_variant_states(variant):
    events = {e["packet_id"]: e for e in variant[0]}
    assert [events[p]["flow_state"] for p in range(1, 7)] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "CLOSED"]
    assert events[10]["flow_state"] == "RESET"


def test_variant_counters(variant):
    line = engine_line(variant[4])
    assert "events_evaluated=10 " in line and "candidate_rules=30 " in line
    assert "rejected_flow=16 " in line and "rejected_packet=8 " in line and "content_evaluations=0 " in line
    assert "matches=6 " in line and "rule_errors=0" in line


# --- evidence and reproducibility --------------------------------------------------------------------------------------------------------------------------

def test_evidence_files_exist_in_both_directories(run, variant):
    for directory in (CASE_DIR, VARIANT_DIR):
        for name in ("events", "flows", "detections", "rules_report"):
            assert (directory / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_the_pcaps_are_reproducible():
    spec = importlib.util.spec_from_file_location("t08_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    for name, packets in (("input.pcap", module.PACKETS), ("variants.pcap", module.VARIANT_PACKETS)):
        rebuilt = Path(write_pcap(packets, str(CASE_DIR / "_rebuilt.pcap")))
        try:
            assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / name).read_bytes()).hexdigest()
        finally:
            rebuilt.unlink(missing_ok=True)
