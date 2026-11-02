"""Rebuild input.pcap for T04 (header parsing). Deterministic: fixed IPs, ports, seq/ack and timestamp.
T04 is about how the headers are parsed; the single SYN only lets main.py run and shows that the parsed
header-only rules behave as parsed (the matching itself is tested in T05)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

PACKETS = [
    tcp_packet("10.0.0.5", 40004, "192.168.1.9", 80, "S", ts=1700000000.0, seq=1000, ack=0),   # 1 SYN
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
