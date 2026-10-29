import pytest

from pcap_builder import tcp_packet, udp_packet, write_pcap       # TEST/helpers is on pytest's pythonpath
from src.capture.pcap_reader import read_pcap
from src.engine.matcher import match_dsize, match_flags
from src.models.event import IDSEvent
from src.models.rule import DsizeSpec, FlagsSpec
from src.pipeline.pipeline import _parse_packet_layers
from src.rules.validator import parse_rule

HEAD = "alert tcp any any -> any any"


def spec(option):
    """The FlagsSpec / DsizeSpec the Parser builds for one option text."""
    rule = parse_rule(f'{HEAD} (msg:"x"; {option}; sid:1;)')
    assert rule.status == "valid", rule
    return rule.rule.flags or rule.rule.dsize


def pkt(flags, payload=b"", proto="TCP", **kw):
    d = dict(packet_id=1, timestamp=1.0, src_ip="1.1.1.1", src_port=1, dst_ip="2.2.2.2", dst_port=2,
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=payload, transport_fields={"flags": flags} if flags is not None else {})
    d.update(kw)
    return IDSEvent(**d)


# --- T12: five packets, hand-computed ---------------------------------------------------------------------

P = {
    "p1": pkt(["SYN"]),
    "p2": pkt(["SYN", "ACK"]),
    "p3": pkt(["ACK"]),
    "p4": pkt(["PSH", "ACK"], b"0123456789"),
    "p5": pkt(["FIN", "ACK"]),
}


def hits(*options):
    specs = [(spec(o), match_flags if o.startswith("flags") else match_dsize) for o in options]
    return [name for name, p in P.items() if all(fn(sp, p) for sp, fn in specs)]


@pytest.mark.parametrize("options, expected", [
    (["flags:S"], ["p1"]),
    (["flags:SA"], ["p2"]),
    (["flags:A"], ["p3"]),
    (["flags:A+"], ["p2", "p3", "p4", "p5"]),
    (["flags:SF*"], ["p1", "p2", "p5"]),
    (["flags:PA", "dsize:10"], ["p4"]),
    (["dsize:0"], ["p1", "p2", "p3", "p5"]),
    (["dsize:<5"], ["p1", "p2", "p3", "p5"]),
    (["dsize:10"], ["p4"]),
    (["dsize:>0"], ["p4"]),
    (["dsize:5<>15"], ["p4"]),
])
def test_t12(options, expected):
    assert hits(*options) == expected


def test_exact_is_not_all():
    # the classic slip: flags:A implemented as flags:A+ would also match p2, p4 and p5
    assert match_flags(spec("flags:A"), P["p4"]) is False
    assert match_flags(spec("flags:A"), P["p5"]) is False
    assert match_flags(spec("flags:A+"), P["p4"]) is True


# --- flags in detail ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("option, flags, expected", [
    ("flags:S", ["SYN"], True),
    ("flags:S", ["SYN", "ACK"], False),
    ("flags:SA", ["ACK", "SYN"], True),                  # order does not matter
    ("flags:SA", ["SYN"], False),
    ("flags:S+", ["SYN"], True),
    ("flags:S+", ["SYN", "ACK", "PSH"], True),
    ("flags:S+", ["ACK"], False),
    ("flags:SA+", ["SYN", "ACK", "URG"], True),
    ("flags:SA+", ["SYN"], False),
    ("flags:S*", ["SYN", "ACK"], True),
    ("flags:S*", ["ACK"], False),
    ("flags:SA*", ["ACK"], True),
    ("flags:SA*", ["FIN"], False),
    ("flags:!S", ["ACK"], True),
    ("flags:!S", ["SYN", "ACK"], False),
    ("flags:!SA", ["PSH"], True),
    ("flags:!SA", ["ACK", "PSH"], False),
    ("flags:!S", [], True),
    ("flags:0", [], True),
    ("flags:0", ["ACK"], False),
    ("flags:0", ["SYN"], False),
    ("flags:FSRPAUCE", ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE"], True),
    ("flags:C", ["CWR"], True),
    ("flags:E", ["ECE"], True),
    ("flags:C", ["ECE"], False),
    ("flags:R", ["RST"], True),
    ("flags:RA", ["RST", "ACK"], True),
    ("flags:U+", ["URG", "PSH"], True),
])
def test_flag_modes(option, flags, expected):
    assert match_flags(spec(option), pkt(flags)) is expected


def test_flag_names_are_case_insensitive_and_accept_tuple_and_set():
    assert match_flags(spec("flags:SA"), pkt(["syn", "Ack"])) is True
    assert match_flags(spec("flags:SA"), pkt(("SYN", "ACK"))) is True
    assert match_flags(spec("flags:SA"), pkt({"SYN", "ACK"})) is True


def test_unknown_flag_name_is_ignored():
    assert match_flags(spec("flags:S"), pkt(["SYN", "BOGUS"])) is True


def test_udp_never_matches_flags():
    for option in ("flags:0", "flags:!S", "flags:S", "flags:S+", "flags:S*"):
        assert match_flags(spec(option), pkt([], proto="UDP")) is False


@pytest.mark.parametrize("event", [
    pkt(None),                                   # no flags key at all
    pkt("SYN"),                                  # a string is not a list
    pkt(5),
    pkt(["SYN"], transport_fields=None),
    pkt(["SYN"], transport_fields="x"),
    pkt(["SYN"], transport_protocol=None),
])
def test_unknown_flags_never_match_and_never_raise(event):
    for option in ("flags:S", "flags:0", "flags:!S"):
        assert match_flags(spec(option), event) is False


def test_missing_attributes():
    class Bare:
        pass
    assert match_flags(spec("flags:S"), Bare()) is False
    assert match_dsize(spec("dsize:0"), Bare()) is True          # no payload attribute = 0 bytes


def test_no_spec_means_no_constraint():
    assert match_flags(None, pkt(["SYN"])) is True and match_flags(None, pkt([], proto="UDP")) is True
    assert match_dsize(None, pkt(["SYN"])) is True


# --- dsize in detail ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("option, size, expected", [
    ("dsize:0", 0, True), ("dsize:0", 1, False),
    ("dsize:10", 10, True), ("dsize:10", 9, False), ("dsize:10", 11, False),
    ("dsize:<10", 9, True), ("dsize:<10", 10, False),
    ("dsize:>10", 11, True), ("dsize:>10", 10, False),
    ("dsize:5<>15", 4, False), ("dsize:5<>15", 5, True), ("dsize:5<>15", 10, True),
    ("dsize:5<>15", 15, True), ("dsize:5<>15", 16, False),
    ("dsize:7<>7", 7, True), ("dsize:7<>7", 8, False),
    ("dsize:<0", 0, False),
    ("dsize:>0", 0, False), ("dsize:>0", 1, True),
])
def test_dsize_ops_and_bounds(option, size, expected):
    assert match_dsize(spec(option), pkt(["ACK"], b"x" * size)) is expected


def test_dsize_uses_the_real_payload_not_payload_length():
    event = pkt(["ACK"], b"abc", payload_length=999)
    assert match_dsize(spec("dsize:3"), event) is True
    assert match_dsize(spec("dsize:999"), event) is False


def test_dsize_empty_none_and_bytearray_payloads():
    assert match_dsize(spec("dsize:0"), pkt(["ACK"], None)) is True
    assert match_dsize(spec("dsize:0"), pkt(["ACK"], b"")) is True
    assert match_dsize(spec("dsize:3"), pkt(["ACK"], bytearray(b"abc"))) is True


def test_dsize_applies_to_udp_too():
    assert match_dsize(spec("dsize:>5"), pkt(None, b"123456", proto="UDP")) is True


@pytest.mark.parametrize("payload", ["abc", 5, ["a"]])
def test_dsize_unmeasurable_payload_does_not_match(payload):
    assert match_dsize(spec("dsize:3"), pkt(["ACK"], payload)) is False


def test_specs_are_the_parser_s_objects():
    assert spec("flags:SA+") == FlagsSpec("all", frozenset("SA"))
    assert spec("dsize:5<>15") == DsizeSpec("range", 5, 15)


# --- through the real parsers (not hand-made events) -------------------------------------------------------------
#
# The matchers assume the Part 1 parser stores full flag names (SYN, ACK, ...) and that the payload is
# the real application data without Ethernet padding. These tests run frames through pcap -> read_pcap ->
# the real packet parser to prove both assumptions, so a rename in the parser cannot silently turn every
# `flags:` rule into a never-match.

A, B = "10.0.0.1", "10.0.0.2"
NON_HTTP_PORT = 9999        # port 80 + a non-HTTP payload would be MALFORMED by the Part 1 HTTP parser


def parse_frames(tmp_path, frames, pad=b""):
    """Write frames to a pcap, read them back and parse each with the real parser."""
    path = write_pcap(frames, str(tmp_path / "t.pcap"))
    events = []
    for i, (ts, raw) in enumerate(read_pcap(path), start=1):
        events.append(_parse_packet_layers(ts, raw + pad, i))
    return events


def t12_frames():
    def tcp(flags, payload=b""):
        return tcp_packet(A, 40000, B, NON_HTTP_PORT, flags, ts=1.0, payload=payload)
    return [tcp("S"), tcp("SA"), tcp("A"), tcp("PA", b"0123456789"), tcp("FA")]


def real_hits(events, *options):
    specs = [(spec(o), match_flags if o.startswith("flags") else match_dsize) for o in options]
    return [f"p{i}" for i, e in enumerate(events, start=1) if all(fn(sp, e) for sp, fn in specs)]


@pytest.mark.parametrize("pad", [b"", b"\x00" * 6])
@pytest.mark.parametrize("options, expected", [
    (["flags:S"], ["p1"]),
    (["flags:SA"], ["p2"]),
    (["flags:A"], ["p3"]),
    (["flags:A+"], ["p2", "p3", "p4", "p5"]),
    (["flags:SF*"], ["p1", "p2", "p5"]),
    (["flags:PA", "dsize:10"], ["p4"]),
    (["dsize:0"], ["p1", "p2", "p3", "p5"]),
    (["dsize:<5"], ["p1", "p2", "p3", "p5"]),
    (["dsize:10"], ["p4"]),
    (["dsize:>0"], ["p4"]),
    (["dsize:5<>15"], ["p4"]),
])
def test_t12_through_the_real_parser_with_and_without_ethernet_padding(tmp_path, options, expected, pad):
    events = parse_frames(tmp_path, t12_frames(), pad)
    assert all(e.status == "OK" for e in events)
    assert real_hits(events, *options) == expected


def test_real_parser_stores_full_flag_names(tmp_path):
    events = parse_frames(tmp_path, t12_frames())
    assert [e.transport_fields["flags"] for e in events] == [
        ["SYN"], ["SYN", "ACK"], ["ACK"], ["PSH", "ACK"], ["FIN", "ACK"]]


def test_ethernet_padding_is_not_counted_in_dsize(tmp_path):
    ack = tcp_packet(A, 40000, B, NON_HTTP_PORT, "A", ts=1.0)
    (event,) = parse_frames(tmp_path, [ack], pad=b"\x00" * 6)
    assert event.payload == b""
    assert match_dsize(spec("dsize:0"), event) is True
    assert match_dsize(spec("dsize:>0"), event) is False


def test_ece_and_cwr_flags_come_through_the_real_parser(tmp_path):
    (event,) = parse_frames(tmp_path, [tcp_packet(A, 40000, B, NON_HTTP_PORT, "AEC", ts=1.0)])
    assert match_flags(spec("flags:ACE"), event) is True
    assert match_flags(spec("flags:A"), event) is False
    assert match_flags(spec("flags:A+"), event) is True


def test_real_udp_packet_has_no_tcp_flags_and_a_dsize(tmp_path):
    (event,) = parse_frames(tmp_path, [udp_packet(A, 5353, B, 53, ts=1.0, payload=b"abcdef")])
    assert match_flags(spec("flags:0"), event) is False
    assert match_dsize(spec("dsize:6"), event) is True
