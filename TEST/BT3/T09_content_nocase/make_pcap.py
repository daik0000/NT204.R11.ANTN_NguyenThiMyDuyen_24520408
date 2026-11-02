"""Rebuild input.pcap and variants.pcap for T09 (content and nocase). Deterministic: fixed IPs, ports, seq/ack and timestamps.

input.pcap     one packet whose payload is "GET /Admin HTTP/1.1"
variants.pcap  one packet whose payload is "GET /ADMIN HTTP/1.1" (the path in capitals)"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

T = 1700000000.0

PACKETS = [
    tcp_packet("10.0.0.1", 40009, "10.0.0.2", 80, "PA", ts=T, seq=1001, ack=7001,
               payload=b"GET /Admin HTTP/1.1\r\nHost: t09.example\r\n\r\n"),
]

VARIANT_PACKETS = [
    tcp_packet("10.0.0.1", 40010, "10.0.0.2", 80, "PA", ts=T + 10.0, seq=1001, ack=7001,
               payload=b"GET /ADMIN HTTP/1.1\r\nHost: t09.example\r\n\r\n"),
]

if __name__ == "__main__":
    for name, packets in (("input.pcap", PACKETS), ("variants.pcap", VARIANT_PACKETS)):
        out = write_pcap(packets, HERE / name)
        print(f"wrote {out} ({len(packets)} packets)")
