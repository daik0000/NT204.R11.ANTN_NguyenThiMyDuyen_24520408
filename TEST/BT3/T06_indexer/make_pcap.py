"""Rebuild input.pcap for T06 (indexer). Deterministic: fixed IPs, ports, seq/ack and timestamps.

Packets 1-7 are the seven (protocol, destination port) pairs of the hand-computed table; packets 8 and 9 are the
two ways round of rule 7 (tcp 443 <> 8443). Every packet comes from source port 40000 + its number, so only
packets 8 and 9 can satisfy the source side of rule 7."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

A, B = "10.0.0.1", "10.0.0.2"
T = 1700000000.0

PACKETS = [
    tcp_packet(A, 40001, B, 80,   "S", ts=T + 1, seq=1000, ack=0),     # 1 tcp/80
    tcp_packet(A, 40002, B, 443,  "S", ts=T + 2, seq=1000, ack=0),     # 2 tcp/443
    tcp_packet(A, 40003, B, 8443, "S", ts=T + 3, seq=1000, ack=0),     # 3 tcp/8443
    tcp_packet(A, 40004, B, 2000, "S", ts=T + 4, seq=1000, ack=0),     # 4 tcp/2000
    udp_packet(A, 40005, B, 53,   ts=T + 5),                           # 5 udp/53
    udp_packet(A, 40006, B, 5500, ts=T + 6),                           # 6 udp/5500
    udp_packet(A, 40007, B, 80,   ts=T + 7),                           # 7 udp/80
    tcp_packet(A, 443,   B, 8443, "S", ts=T + 8, seq=2000, ack=0),     # 8 tcp 443 -> 8443 (rule 7, forward)
    tcp_packet(B, 8443,  A, 443,  "S", ts=T + 9, seq=3000, ack=0),     # 9 tcp 8443 -> 443 (rule 7, reverse)
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
