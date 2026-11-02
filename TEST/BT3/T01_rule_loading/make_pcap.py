"""Rebuild input.pcap for T01 (rule loading). Deterministic: fixed IPs, ports, seq/ack and timestamp.
T01 is about reading the rule file, so the traffic is a single SYN: it only lets main.py run."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

PACKETS = [
    tcp_packet("10.0.0.1", 40001, "10.0.0.2", 80, "S", ts=1700000000.0, seq=1000, ack=0),   # 1 SYN
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
