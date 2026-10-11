"""Rebuild input.pcap for T09 (TCP close). Deterministic: fixed IPs, ports, seq/ack and timestamps.
Flow 1 = normal close (FIN/ACK both ways + final ACK), Flow 2 = RST (plus a late ACK after it),
Flow 3 = half-close (one FIN only). Every timestamp stays within 14 s so the 10 s CLOSED linger of
flow 1 (state changed at T+5) never expires before the pcap ends."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

C, S = "10.0.0.1", "10.0.0.2"
T = 1700000000.0

PACKETS = [
    # --- flow 1 (client port 40301): normal close ---
    tcp_packet(C, 40301, S, 80, "S",  ts=T + 0.0, seq=1000, ack=0),        # 1 SYN
    tcp_packet(S, 80, C, 40301, "SA", ts=T + 1.0, seq=7000, ack=1001),     # 2 SYN/ACK
    tcp_packet(C, 40301, S, 80, "A",  ts=T + 2.0, seq=1001, ack=7001),     # 3 ACK
    tcp_packet(C, 40301, S, 80, "FA", ts=T + 3.0, seq=1001, ack=7001),     # 4 FIN/ACK client
    tcp_packet(S, 80, C, 40301, "A",  ts=T + 4.0, seq=7001, ack=1002),     # 5 ACK of the FIN
    tcp_packet(S, 80, C, 40301, "FA", ts=T + 5.0, seq=7001, ack=1002),     # 6 FIN/ACK server -> both FINs seen
    tcp_packet(C, 40301, S, 80, "A",  ts=T + 6.0, seq=1002, ack=7002),     # 7 final ACK (after CLOSED)
    # --- flow 2 (client port 40302): reset ---
    tcp_packet(C, 40302, S, 80, "S",  ts=T + 7.0, seq=2000, ack=0),        # 8 SYN
    tcp_packet(S, 80, C, 40302, "SA", ts=T + 8.0, seq=8000, ack=2001),     # 9 SYN/ACK
    tcp_packet(C, 40302, S, 80, "A",  ts=T + 9.0, seq=2001, ack=8001),     # 10 ACK
    tcp_packet(C, 40302, S, 80, "R",  ts=T + 10.0, seq=2001, ack=0),       # 11 RST
    tcp_packet(S, 80, C, 40302, "A",  ts=T + 11.0, seq=8001, ack=2001),    # 12 late ACK after RST
    # --- flow 3 (client port 40303): half-close, then silence ---
    tcp_packet(C, 40303, S, 80, "S",  ts=T + 12.0, seq=3000, ack=0),       # 13 SYN
    tcp_packet(S, 80, C, 40303, "SA", ts=T + 12.5, seq=9000, ack=3001),    # 14 SYN/ACK
    tcp_packet(C, 40303, S, 80, "A",  ts=T + 13.0, seq=3001, ack=9001),    # 15 ACK
    tcp_packet(C, 40303, S, 80, "FA", ts=T + 13.5, seq=3001, ack=9001),    # 16 FIN/ACK client only
    tcp_packet(S, 80, C, 40303, "A",  ts=T + 14.0, seq=9001, ack=3002),    # 17 ACK of the FIN, no FIN back
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")