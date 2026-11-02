import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.rules.indexer import RuleIndexer
from src.rules.repository import RuleRepository

CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[2]

# --- worked out by hand BEFORE running anything -------------------------------------------------------------------
# rules.rules (rule n has sid 6000 + n):
#   1 tcp any -> 80 | 2 tcp any -> 1:1024 | 3 tcp any -> any | 4 udp any -> 53 | 5 ip any -> any
#   6 udp any -> 5000:6000 | 7 tcp 443 <> 8443
# The index looks only at the protocol and the destination port; a "<>" rule is also filed under its SOURCE port.
#   (tcp, 80)    1 yes (80)   2 yes (80 in 1:1024)   3 yes   4 no (udp)   5 yes (ip)   6 no   7 no            -> 1 2 3 5
#   (tcp, 443)   1 no         2 yes                  3 yes              5 yes            7 yes (src port 443) -> 2 3 5 7
#   (tcp, 8443)  1 no         2 no (> 1024)          3 yes              5 yes            7 yes (dst port 8443)-> 3 5 7
#   (tcp, 2000)  1 no         2 no                   3 yes              5 yes            7 no                 -> 3 5
#   (udp, 53)    4 yes        5 yes                  6 no (< 5000)                                            -> 4 5
#   (udp, 5500)  4 no         5 yes                  6 yes (5500 in 5000:6000)                                -> 5 6
#   (udp, 80)    4 no         5 yes                  6 no                                                     -> 5
TABLE = [
    ("tcp", 80, [1, 2, 3, 5]),
    ("tcp", 443, [2, 3, 5, 7]),
    ("tcp", 8443, [3, 5, 7]),
    ("tcp", 2000, [3, 5]),
    ("udp", 53, [4, 5]),
    ("udp", 5500, [5, 6]),
    ("udp", 80, [5]),
]
TOTAL_RULES = 7


def sid(n):
    return 6000 + n


# input.pcap: packets 1-7 are the pairs of the table (source port 40000 + n), packet 8 is tcp 443 -> 8443 and
# packet 9 is tcp 8443 -> 443. The index only offers candidates; the header stage then decides.
#   packet | candidates   | header-only rules that really match
#     1    | 1 2 3 5      | 1 2 3 5
#     2    | 2 3 5 7      | 2 3 5          (rule 7 needs source port 443 or 8443: 40002 is neither -> rejected)
#     3    | 3 5 7        | 3 5            (rule 7 rejected: source port 40003)
#     4    | 3 5          | 3 5
#     5    | 4 5          | 4 5
#     6    | 5 6          | 5 6
#     7    | 5            | 5
#     8    | 3 5 7        | 3 5 7          (443 -> 8443: rule 7 forward)
#     9    | 2 3 5 7      | 2 3 5 7        (8443 -> 443: rule 7 reversed; it is a candidate only because "<>" is filed under port 443)
CANDIDATES_BY_PACKET = {1: [1, 2, 3, 5], 2: [2, 3, 5, 7], 3: [3, 5, 7], 4: [3, 5], 5: [4, 5], 6: [5, 6], 7: [5],
                        8: [3, 5, 7], 9: [2, 3, 5, 7]}
DETECTIONS_BY_PACKET = {1: [1, 2, 3, 5], 2: [2, 3, 5], 3: [3, 5], 4: [3, 5], 5: [4, 5], 6: [5, 6], 7: [5],
                        8: [3, 5, 7], 9: [2, 3, 5, 7]}
TOTAL_CANDIDATES = 4 + 4 + 3 + 2 + 2 + 2 + 1 + 3 + 4         # 25
TOTAL_DETECTIONS = 4 + 3 + 2 + 2 + 2 + 2 + 1 + 3 + 4         # 23
REJECTED_BY_HEADER = 2                                        # rule 7 on packets 2 and 3
WITHOUT_AN_INDEX = 9 * TOTAL_RULES                            # 63 rule tests if every rule were tried on every packet


@pytest.fixture(scope="module")
def indexer():
    _, _, rules = run_rules_only(CASE_DIR / "rules.rules")
    repo = RuleRepository()
    for rule in rules:
        repo.add(rule)
    repo.freeze()
    return RuleIndexer(repo)


def sids(rules):
    return [r.sid for r in rules]


# --- the table ----------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("protocol, port, expected", TABLE, ids=[f"{p}/{n}" for p, n, _ in TABLE])
def test_candidates_of_each_pair(indexer, protocol, port, expected):
    assert sids(indexer.candidates(protocol, port)) == [sid(n) for n in expected]      # same sids, same order


def test_all_seven_rules_were_loaded(indexer):
    assert len(indexer) == TOTAL_RULES


def test_the_index_does_not_walk_every_rule(indexer):
    counts = {(p, n): len(indexer.candidates(p, n)) for p, n, _ in TABLE}
    assert counts[("tcp", 2000)] == 2 < TOTAL_RULES                       # 2 of 7: rules 3 and 5 only
    assert counts[("udp", 80)] == 1
    assert all(count < TOTAL_RULES for count in counts.values())
    assert sum(counts.values()) == 18                                      # 4+4+3+2+2+2+1, against 7 x 7 = 49 without an index


def test_results_are_in_rule_order(indexer):
    for protocol, port, expected in TABLE:
        found = sids(indexer.candidates(protocol, port))
        assert found == sorted(found) and found == [sid(n) for n in expected]


def test_a_bidirectional_rule_is_offered_for_its_source_port_too(indexer):
    assert sid(7) in sids(indexer.candidates("tcp", 443))                  # 443 is rule 7's SOURCE port
    assert sid(7) in sids(indexer.candidates("tcp", 8443))
    assert sid(1) not in sids(indexer.candidates("tcp", 443))              # a one-way rule is filed under its destination only


@pytest.mark.parametrize("protocol", ["icmp", "arp", "", None, "http", "tcpp"])
def test_an_unknown_protocol_gives_no_candidates_and_no_error(indexer, protocol):
    assert indexer.candidates(protocol, 80) == []


@pytest.mark.parametrize("port", [None, -1, 65536, "80"])
def test_a_bad_port_gives_no_candidates_and_no_error(indexer, port):
    assert indexer.candidates("tcp", port) == []


def test_protocol_letter_case_is_ignored(indexer):
    assert sids(indexer.candidates("TCP", 80)) == [sid(n) for n in (1, 2, 3, 5)]


def test_the_boundaries_of_the_range_rules(indexer):
    assert sid(2) in sids(indexer.candidates("tcp", 1)) and sid(2) in sids(indexer.candidates("tcp", 1024))
    assert sid(2) not in sids(indexer.candidates("tcp", 0)) and sid(2) not in sids(indexer.candidates("tcp", 1025))
    assert sid(6) in sids(indexer.candidates("udp", 5000)) and sid(6) in sids(indexer.candidates("udp", 6000))
    assert sid(6) not in sids(indexer.candidates("udp", 4999)) and sid(6) not in sids(indexer.candidates("udp", 6001))


def test_candidates_are_written_as_evidence(indexer):
    lines = [json.dumps({"protocol": p, "dst_port": n, "sids": sids(indexer.candidates(p, n))}) for p, n, _ in TABLE]
    (CASE_DIR / "candidates.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = [json.loads(line) for line in (CASE_DIR / "candidates.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(r["protocol"], r["dst_port"], [s - 6000 for s in r["sids"]]) for r in rows] == TABLE


# --- through main.py: the same index in a real run -----------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def run():
    stderr = []
    return run_case_ids(CASE_DIR, rules=["rules.rules"], stderr_out=stderr) + (stderr[0],)


def test_detections_per_packet(run):
    per_packet = {}
    for d in run[2]:
        per_packet.setdefault(d["packet_id"], []).append(d["sid"])
    assert per_packet == {p: [sid(n) for n in rules] for p, rules in DETECTIONS_BY_PACKET.items()}
    assert len(run[2]) == TOTAL_DETECTIONS


def test_rule_7_fires_for_both_ways_round_only_on_packets_8_and_9(run):
    fired = {d["packet_id"] for d in run[2] if d["sid"] == sid(7)}
    assert fired == {8, 9}                                                 # the packets from other source ports are rejected by the header


def test_the_counters_prove_the_index_saves_work(run):
    line = [l for l in run[4].splitlines() if "System shutdown complete" in l][-1]
    assert f"events_evaluated=9, candidates={TOTAL_CANDIDATES}, detections={TOTAL_DETECTIONS}" in line
    engine = [l for l in run[4].splitlines() if "| engine:" in l][-1]
    assert f"candidate_rules={TOTAL_CANDIDATES}" in engine and f"rejected_header={REJECTED_BY_HEADER}" in engine
    assert f"matches={TOTAL_DETECTIONS}" in engine and "rule_errors=0" in engine
    assert TOTAL_CANDIDATES == sum(len(v) for v in CANDIDATES_BY_PACKET.values()) < WITHOUT_AN_INDEX == 63


def test_rules_report_and_evidence_files(run):
    assert [(r["status"], r["sid"]) for r in run[3]] == [("valid", sid(n)) for n in range(1, 8)]
    for name in ("events", "flows", "detections", "rules_report"):
        assert (CASE_DIR / f"{name}.jsonl").is_file()
    assert len(run[0]) == 9 and str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t06_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
