import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case_ids, run_rules_only
from src.models.rule import IpSpec, PortSpec

CASE_DIR = Path(__file__).resolve().parent
ROOT = CASE_DIR.parents[2]

ANY_IP = IpSpec(any=True)
ANY_PORT = PortSpec(0, 65535)

# Worked out by hand (a.b.c.d = a*2**24 + b*2**16 + c*2**8 + d; a /n mask has n leading ones), BEFORE running.
#   10.0.0.5         = 167772160 + 5            = 167772165      mask /32 = 0xFFFFFFFF
#   192.168.1.0      = 3221225472 + 11010048 + 256 = 3232235776   mask /24 = 0xFFFFFF00
#   10.0.0.0/8                                  = 167772160      mask /8  = 0xFF000000
#   10.0.0.5/24: host bits cleared -> 10.0.0.0  = 167772160      mask /24 = 0xFFFFFF00
#   172.16.0.0/12                               = 2886729728     mask /12 = 0xFFF00000
#   255.255.255.255                             = 4294967295     mask /32 = 0xFFFFFFFF
# rule sid -> (protocol, src_ip, src_port, direction, dst_ip, dst_port)
EXPECTED = {
    4001: ("tcp", ANY_IP, ANY_PORT, "->", ANY_IP, PortSpec(80, 80)),
    4002: ("tcp", IpSpec(False, 167772165, 0xFFFFFFFF), ANY_PORT, "->", IpSpec(False, 3232235776, 0xFFFFFF00), PortSpec(1, 1024)),
    4003: ("udp", IpSpec(False, 167772160, 0xFF000000), PortSpec(0, 1023), "->", ANY_IP, PortSpec(5000, 65535)),
    4004: ("tcp", IpSpec(False, 167772160, 0xFFFFFF00), ANY_PORT, "<>", ANY_IP, ANY_PORT),
}
EXPECTED_VARIANTS = {
    4101: ("ip", ANY_IP, ANY_PORT, "->", ANY_IP, ANY_PORT),
    4102: ("tcp", IpSpec(False, 0xC0A8014D, 0xFFFFFFFF), PortSpec(80, 80), "->", IpSpec(False, 167772160, 0xFFFFFFFC), PortSpec(0, 0)),
    4103: ("tcp", IpSpec(False, 0, 0), PortSpec(0, 65535), "->", ANY_IP, ANY_PORT),
    4104: ("udp", IpSpec(False, 2886729728, 0xFFF00000), ANY_PORT, "->", IpSpec(False, 4294967295, 0xFFFFFFFF), PortSpec(65535, 65535)),
}
# 192.168.1.77 = 3232235776 + 77 = 3232235853 = 0xC0A8014D ;  10.0.0.0/30 -> mask 0xFFFFFFFC


def header_of(rule):
    return (rule.protocol, rule.src_ip, rule.src_port, rule.direction, rule.dst_ip, rule.dst_port)


@pytest.fixture(scope="module")
def parsed():
    report, records, rules = run_rules_only([CASE_DIR / "rules.rules", CASE_DIR / "variants.rules"])
    return report, records, {r.sid: r for r in rules}


# --- the literal numbers of the hand calculation ----------------------------------------------------------------------

def test_the_hand_numbers_are_right():
    assert 10 * 2**24 + 5 == 167772165 and 10 * 2**24 == 167772160
    assert 192 * 2**24 + 168 * 2**16 + 1 * 2**8 == 3232235776
    assert 172 * 2**24 + 16 * 2**16 == 2886729728 and 192 * 2**24 + 168 * 2**16 + 1 * 2**8 + 77 == 0xC0A8014D
    assert (0xFFFFFFFF << (32 - 24)) & 0xFFFFFFFF == 0xFFFFFF00 and (0xFFFFFFFF << (32 - 12)) & 0xFFFFFFFF == 0xFFF00000


@pytest.mark.parametrize("sid", sorted(EXPECTED))
def test_rules_file_header_fields(parsed, sid):
    assert header_of(parsed[2][sid]) == EXPECTED[sid]


@pytest.mark.parametrize("sid", sorted(EXPECTED_VARIANTS))
def test_variants_file_header_fields(parsed, sid):
    assert header_of(parsed[2][sid]) == EXPECTED_VARIANTS[sid]


def test_the_values_the_issue_lists_explicitly(parsed):
    rules = parsed[2]
    assert (rules[4002].src_ip.network, rules[4002].src_ip.mask) == (167772165, 0xFFFFFFFF)
    assert (rules[4002].dst_ip.network, rules[4002].dst_ip.mask) == (3232235776, 0xFFFFFF00)
    assert (rules[4002].dst_port.lo, rules[4002].dst_port.hi) == (1, 1024)
    assert (rules[4003].src_port.lo, rules[4003].src_port.hi) == (0, 1023)          # ":1023"
    assert (rules[4003].dst_port.lo, rules[4003].dst_port.hi) == (5000, 65535)      # "5000:"
    assert (rules[4004].src_ip.network, rules[4004].src_ip.mask) == (167772160, 0xFFFFFF00)   # 10.0.0.5/24 -> 10.0.0.0/24


def test_any_is_a_flag_and_the_full_port_range_is_any(parsed):
    assert parsed[2][4001].src_ip.any and parsed[2][4001].src_port.is_any and parsed[2][4001].dst_ip.any
    assert not parsed[2][4103].src_ip.any                     # 0.0.0.0/0 is spelled out, though it matches the same addresses
    assert parsed[2][4103].src_port.is_any                    # 0:65535 is the same as "any"
    assert not parsed[2][4002].dst_port.is_any and not parsed[2][4102].dst_port.is_any


def test_protocol_and_direction(parsed):
    rules = parsed[2]
    assert {s: r.protocol for s, r in rules.items()} == {
        4001: "tcp", 4002: "tcp", 4003: "udp", 4004: "tcp", 4101: "ip", 4102: "tcp", 4103: "tcp", 4104: "udp"}
    assert {s: r.direction for s, r in rules.items() if r.direction == "<>"} == {4004: "<>"}
    assert all(r.action == "alert" for r in rules.values())


def test_a_header_only_rule_has_no_contents_and_the_defaults(parsed):
    for rule in parsed[2].values():
        assert rule.contents == ()
        assert (rule.flow, rule.flags, rule.dsize, rule.classtype, rule.passive_options) == (None, None, None, None, ())
        assert (rule.rev, rule.priority) == (1, 3)


def test_every_rule_is_valid_and_counted(parsed):
    report, records, _ = parsed
    assert [r.status for r in records] == ["valid"] * 8 and [r.sid for r in records] == [
        4001, 4002, 4003, 4004, 4101, 4102, 4103, 4104]
    assert (report.total_lines, report.comment, report.rule_lines, report.valid, report.invalid, report.unsupported) == (10, 2, 8, 8, 0, 0)


def test_rule_objects_remember_where_they_came_from(parsed):
    rule = parsed[2][4002]
    assert rule.source_file.endswith("rules.rules") and rule.line_no == 3
    assert rule.raw == 'alert tcp 10.0.0.5 any -> 192.168.1.0/24 1:1024 (msg:"T04 host to subnet"; sid:4002;)'


# --- through main.py -----------------------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cli():
    stderr = []
    out = run_case_ids(CASE_DIR, rules=["rules.rules", "variants.rules"], stderr_out=stderr)
    return out + (stderr[0],)


def test_main_py_reports_all_eight_rules_as_valid(cli):
    report = cli[3]
    assert [(r["status"], r["reason"], r["sid"]) for r in report] == [("valid", None, sid) for sid in
                                                                        [4001, 4002, 4003, 4004, 4101, 4102, 4103, 4104]]
    assert "rejected" not in cli[4].replace("rejected_", "")           # no rule was rejected (the stats line has "rejected_header=")


def test_the_parsed_headers_behave_on_the_packet(cli):
    # TCP SYN 10.0.0.5:40004 -> 192.168.1.9:80, worked out by hand:
    #   4001 any -> port 80 yes | 4002 host 10.0.0.5 -> 192.168.1.0/24, port 80 in 1:1024 yes | 4003 udp no
    #   4004 10.0.0.0/24 <> any yes | 4101 ip any yes | 4102 src 192.168.1.77:80 no | 4103 tcp 0.0.0.0/0 yes | 4104 udp no
    _, _, detections, _, _ = cli
    assert [d["sid"] for d in detections] == [4001, 4002, 4004, 4101, 4103]
    assert all(d["matched"] == [{"keyword": "header"}] and d["packet_id"] == 1 for d in detections)


def test_evidence_files_are_in_the_case_directory(cli):
    for name in ("events", "flows", "detections", "rules_report"):
        assert (CASE_DIR / f"{name}.jsonl").is_file()
    assert str(ROOT) not in (CASE_DIR / "rules_report.jsonl").read_text(encoding="utf-8")


def test_input_pcap_is_reproducible():
    spec = importlib.util.spec_from_file_location("t04_make_pcap", CASE_DIR / "make_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from pcap_builder import write_pcap
    rebuilt = Path(write_pcap(module.PACKETS, str(CASE_DIR / "_rebuilt.pcap")))
    try:
        assert hashlib.md5(rebuilt.read_bytes()).hexdigest() == hashlib.md5((CASE_DIR / "input.pcap").read_bytes()).hexdigest()
    finally:
        rebuilt.unlink(missing_ok=True)
