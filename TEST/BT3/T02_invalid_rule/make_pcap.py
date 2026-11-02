"""Rebuild input.pcap for T02 (invalid rules). Deterministic: fixed IPs, ports, seq/ack and timestamp.
One HTTP request to port 80: it matches the only valid rule (sid 2001, content "GET"), which must keep
working although the rules around it are broken."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

REQUEST = b"GET /index.html HTTP/1.1\r\nHost: t02.example\r\n\r\n"

PACKETS = [
    tcp_packet("10.0.0.1", 40002, "10.0.0.2", 80, "PA", ts=1700000000.0, seq=1001, ack=7001, payload=REQUEST),   # 1
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
