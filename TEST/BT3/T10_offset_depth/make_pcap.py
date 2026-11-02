"""Rebuild input.pcap for T10 (offset and depth). Deterministic: fixed IPs, ports and timestamp.
One UDP datagram to port 9999 (no parser for it, so the payload is raw bytes) carrying the 10 bytes ABCDEFGHIJ."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import udp_packet, write_pcap

PACKETS = [
    udp_packet("10.0.0.1", 40010, "10.0.0.2", 9999, ts=1700000000.0, payload=b"ABCDEFGHIJ"),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
