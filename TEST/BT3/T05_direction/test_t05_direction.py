import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids

CASE_DIR = Path(__file__).resolve().parent
VARIANT_DIR = CASE_DIR / "variant_fixed_ports"      # evidence of the second run (variants.rules + variants.pcap)
ROOT = CASE_DIR.parents[2]

# --- worked out by hand, before running anything ---------------------------------------------------------------
# rules.rules:  5001  alert tcp 10.0.0.5 any -> 192.168.1.20 80      5002  the same header with <>
# input.pcap:   1  10.0.0.5:52133   -> 192.168.1.20:80   (forward)
#               2  192.168.1.20:80  -> 10.0.0.5:52133   (reverse)
#               3  10.9.9.9:52133   -> 192.168.1.20:80   (another source)
#
#     packet | 5001 (->) | 5002 (<>)
#        1   |   MATCH   |   MATCH
#        2   |  NO MATCH |   MATCH      <- only the bidirectional rule sees the reply
#        3   |  NO MATCH |  NO MATCH
#
# detections: 5001 matches 1 packet, 5002 matches 2, packet 3 matches nothing -> 3 in all.
TABLE = {1: {5001: True, 5002: True}, 2: {5001: False, 5002: True}, 3: {5001: False, 5002: False}}
# Indexer candidates (protocol + destination port; a "<>" rule is also filed under its source port):
#   packet 1 (dst 80): 5001, 5002   packet 2 (dst 52133): 5002 only   packet 3 (dst 80): 5001, 5002   -> 5 in all
# the 2 candidates of packet 3 fail the header stage.
#
# variants.rules (the ports are fixed): 5101 ... 10.0.0.5 52133 -> 192.168.1.20 80 ; 5102 the same with <>
# variants.pcap: v1 forward | v2 exact reverse | v3 only the IPs swapped | v4 only the ports swapped
#     packet | 5101 | 5102
#       v1   |  yes |  yes
#       v2   |  no  |  yes
#       v3   |  no  |  no      (192.168.1.20:52133 -> 10.0.0.5:80: IPs swapped but the ports are not)
#       v4   |  no  |  no      (10.0.0.5:80 -> 192.168.1.20:52133: ports swapped but the IPs are not)
VARIANT_TABLE = {1: {5101: True, 5102: True}, 2: {5101: False, 5102: True},
                 3: {5101: False, 5102: False}, 4: {5101: False, 5102: False}}


def expected_detections(table):
    return [(packet, sid) for packet in sorted(table) for sid in sorted(table[packet]) if table[packet][sid]]


@pytest.fixture(scope="module")
def run():
    stderr = []
    out = run_case_ids(CASE_DIR, rules=["rules.rules"], stderr_out=stderr)
    return out + (stderr[0],)


@pytest.fixture(scope="module")
def variant():
    VARIANT_DIR.mkdir(exist_ok=True)
    stderr = []
    out = run_case_ids(VARIANT_DIR, rules=[CASE_DIR / "variants.rules"], pcap_name="../variants.pcap", stderr_out=stderr)
    return out + (stderr[0],)


def summary(stderr):
    return [line for line in stderr.splitlines() if "System shutdown complete" in line][-1]


# --- the table of the issue -----------------------------------------------------------------------------------------

def test_detections_are_exactly_the_matches_of_the_table(run):
    got = [(d["packet_id"], d["sid"]) for d in run[2]]
    assert got == expected_detections(TABLE) == [(1, 5001), (1, 5002), (2, 5002)]


@pytest.mark.parametrize("packet", [1, 2, 3])
@pytest.mark.parametrize("sid", [5001, 5002])
def test_each_cell_of_the_table(run, packet, sid):
    fired = {(d["packet_id"], d["sid"]) for d in run[2]}
    assert ((packet, sid) in fired) is TABLE[packet][sid]


def test_the_totals(run):
    detections = run[2]
    assert len(detections) == 3
    assert sum(d["sid"] == 5001 for d in detections) == 1 and sum(d["sid"] == 5002 for d in detections) == 2
    assert not any(d["packet_id"] == 3 for d in detections)            # the packet from 10.9.9.9 matches nothing


def test_both_rules_are_valid_and_header_only(run):
    report = run[3]
    assert [(r["line"], r["status"], r["sid"]) for r in report] == [(2, "valid", 5001), (3, "valid", 5002)]
    assert all(d["matched"] == [{"keyword": "header"}] for d in run[2])


def test_the_reply_is_reported_with_its_own_addresses_and_the_role_of_its_sender(run):
    by_packet = {(d["packet_id"], d["sid"]): d for d in run[2]}
    request, reply = by_packet[(1, 5002)], by_packet[(2, 5002)]
    assert (request["src_ip"], request["src_port"], request["dst_ip"], request["dst_port"]) == ("10.0.0.5", 52133, "192.168.1.20", 80)
    assert (reply["src_ip"], reply["src_port"], reply["dst_ip"], reply["dst_port"]) == ("192.168.1.20", 80, "10.0.0.5", 52133)
    assert request["flow_direction"] == "to_server" and reply["flow_direction"] == "to_client"
    assert request["flow_id"] == reply["flow_id"]                       # one connection, two directions


def test_the_indexer_only_offers_a_bidirectional_rule_for_the_reply(run):
    line = summary(run[4])
    # candidates: packet 1 -> 5001, 5002 | packet 2 -> 5002 | packet 3 -> 5001, 5002  = 5 ; the 5001 rule is not even tried on the reply
    assert "rules(loaded=2, invalid=0, unsupported=0), events_evaluated=3, candidates=5, detections=3" in line
    engine_line = [l for l in run[4].splitlines() if "| engine:" in l][-1]
    assert "rejected_header=2" in engine_line and "matches=3" in engine_line and "rule_errors=0" in engine_line


def test_main_py_processed_the_three_packets(run):
    events, flows, _, _, _ = run
    assert [e["packet_id"] for e in events] == [1, 2, 3] and len(flows) == 2       # one flow for 1+2, one for 3


# --- variant: fixed ports, a reversed packet must swap IP and port together ---------------------------------------------------

def test_variant_detections_follow_the_variant_table(variant):
    got = [(d["packet_id"], d["sid"]) for d in variant[2]]
    assert got == expected_detections(VARIANT_TABLE) == [(1, 5101), (1, 5102), (2, 5102)]


@pytest.mark.parametrize("packet", [3, 4])
def test_swapping_only_the_ips_or_only_the_ports_is_not_a_reply(variant, packet):
    assert not any(d["packet_id"] == packet for d in variant[2])


def test_variant_counters(variant):
    # candidates: v1 5101, 5102 | v2 5102 | v3 5101, 5102 | v4 5102  = 6 ; the 3 of v3 and v4 fail the header stage
    assert "events_evaluated=4, candidates=6, detections=3" in summary(variant[4])
    engine_line = [l for l in variant[4].splitlines() if "| engine:" in l][-1]
    assert "rejected_header=3" in engine_line and "matches=3" in engine_line


def test_variant_evidence_files_exist():
    for name in ("events", "flows", "detections", "rules_report"):
        assert (VARIANT_DIR / f"{name}.jsonl").is_file()


# --- evidence and reproducibility ---------------------------------------------------------------------------------------------

def test_evidence_files_are_in_the_case_directory(run):
    for name in ("events", "flows", "detections", "rules_report"):
        assert (CASE_DIR / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_the_pcaps_are_reproducible():
    spec = importlib.util.spec_from_file_location("t05_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    for name, packets in (("input.pcap", module.PACKETS), ("variants.pcap", module.VARIANT_PACKETS)):
        rebuilt = Path(write_pcap(packets, str(CASE_DIR / "_rebuilt.pcap")))
        try:
            assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / name).read_bytes()).hexdigest()
        finally:
            rebuilt.unlink(missing_ok=True)
