"""Rebuild input.pcap for T13 (statistics). One TCP connection 10.0.0.1:40601 -> 10.0.0.2:9000:
handshake, four data packets of known size in both directions (10, 20, 30, 40 bytes), FIN/ACK both ways.
Deterministic: fixed IPs, ports, seq/ack and timestamps (packet i is sent at T + i - 1)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

C, S = "10.0.0.1", "10.0.0.2"
T = 1700000000.0

PACKETS = [
    tcp_packet(C, 40601, S, 9000, "S",  ts=T + 0, seq=1000, ack=0),                              # 1 SYN
    tcp_packet(S, 9000, C, 40601, "SA", ts=T + 1, seq=7000, ack=1001),                           # 2 SYN/ACK
    tcp_packet(C, 40601, S, 9000, "A",  ts=T + 2, seq=1001, ack=7001),                           # 3 ACK
    tcp_packet(C, 40601, S, 9000, "PA", ts=T + 3, seq=1001, ack=7001, payload=b"a" * 10),        # 4 data C->S, 10 bytes
    tcp_packet(S, 9000, C, 40601, "PA", ts=T + 4, seq=7001, ack=1011, payload=b"b" * 20),        # 5 data S->C, 20 bytes
    tcp_packet(C, 40601, S, 9000, "PA", ts=T + 5, seq=1011, ack=7021, payload=b"c" * 30),        # 6 data C->S, 30 bytes
    tcp_packet(S, 9000, C, 40601, "PA", ts=T + 6, seq=7021, ack=1041, payload=b"d" * 40),        # 7 data S->C, 40 bytes
    tcp_packet(C, 40601, S, 9000, "FA", ts=T + 7, seq=1041, ack=7061),                           # 8 FIN/ACK client
    tcp_packet(S, 9000, C, 40601, "FA", ts=T + 8, seq=7061, ack=1042),                           # 9 FIN/ACK server -> CLOSED
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")