"""Rebuild input.pcap for T11 (distance and within). Deterministic: fixed IPs, ports, seq/ack and timestamps.

Two TCP packets whose payloads are not HTTP; they go to ports 9001 and 9002 (no parser for either), so that the
payload is raw bytes and each rule applies to its own packet through its destination port.
  packet 1  10.0.0.1:40011 -> 10.0.0.2:9001   AAA-BBB-CCC-BBB   (15 bytes)
  packet 2  10.0.0.1:40012 -> 10.0.0.2:9002   BBB----BBB-CCC    (14 bytes)"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

T = 1700000000.0

PACKETS = [
    tcp_packet("10.0.0.1", 40011, "10.0.0.2", 9001, "PA", ts=T + 0.0, seq=1001, ack=7001, payload=b"AAA-BBB-CCC-BBB"),
    tcp_packet("10.0.0.1", 40012, "10.0.0.2", 9002, "PA", ts=T + 1.0, seq=1001, ack=7001, payload=b"BBB----BBB-CCC"),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
