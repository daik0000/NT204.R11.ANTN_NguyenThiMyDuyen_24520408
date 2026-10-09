import json

from pcap_builder import tcp_packet
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether

from src.logging.jsonl_logger import JSONLLogger
from src.pipeline.pipeline import process_packet

PAD = b"\x00" * 6          # simulated Ethernet padding
BASE = 1700000000.0
HTTP = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"


def _tcp(flags, payload=b"", pad=b""):
    pkt = tcp_packet("10.0.0.1", 1234, "10.0.0.2", 80, flags, ts=BASE, payload=payload)
    return bytes(pkt) + pad


def test_payload_is_exact_even_with_ethernet_padding():
    assert process_packet(BASE, _tcp("PA", HTTP, PAD), 1).payload == HTTP


def test_ack_only_with_padding_has_empty_bytes():
    assert process_packet(BASE, _tcp("A", pad=PAD), 1).payload == b""


def test_truncated_packet_has_no_payload():
    ev = process_packet(BASE, _tcp("S")[:30], 1)
    assert ev.status == "MALFORMED" and ev.payload is None


def test_non_tcp_udp_has_no_payload():
    raw = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
    assert process_packet(BASE, raw, 1).payload is None


def test_logger_writes_the_line_without_payload(tmp_path):
    ev = process_packet(BASE, _tcp("PA", HTTP), 1)
    path = tmp_path / "e.jsonl"
    with JSONLLogger(str(path)) as lg:
        lg.log_event(ev)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1                      # logger swallows errors, so check the line exists
    assert "payload" not in json.loads(lines[0])