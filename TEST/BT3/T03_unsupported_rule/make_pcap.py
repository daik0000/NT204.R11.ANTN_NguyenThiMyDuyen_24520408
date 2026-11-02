"""Rebuild input.pcap for T03 (unsupported rules). Deterministic: fixed IPs, ports, seq/ack and timestamp.
One HTTP request to port 80. Every rule of rules.rules would match it if the unsupported part were
ignored; only the two valid rules (sid 3001 and 3015) may fire."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

REQUEST = b"GET /index.html HTTP/1.1\r\nHost: t03.example\r\n\r\n"

PACKETS = [
    tcp_packet("10.0.0.1", 40003, "10.0.0.2", 80, "PA", ts=1700000000.0, seq=1001, ack=7001, payload=REQUEST),   # 1
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
