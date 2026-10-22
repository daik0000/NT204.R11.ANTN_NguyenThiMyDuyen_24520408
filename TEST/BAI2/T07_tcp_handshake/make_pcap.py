"""Rebuild input.pcap for T07 (TCP handshake). Deterministic: fixed IPs, ports, seq/ack and timestamps.
Connection A = clean 3-way handshake. Connection B = same handshake preceded by a SYN retransmit."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

C, S = "10.0.0.1", "10.0.0.2"
T = 1700000000.0

PACKETS = [
    # --- connection A (client port 40101) ---
    tcp_packet(C, 40101, S, 80, "S",  ts=T + 0.0, seq=1000, ack=0),      # 1 SYN
    tcp_packet(S, 80, C, 40101, "SA", ts=T + 1.0, seq=7000, ack=1001),   # 2 SYN/ACK
    tcp_packet(C, 40101, S, 80, "A",  ts=T + 2.0, seq=1001, ack=7001),   # 3 ACK
    # --- connection B (client port 40102): SYN is retransmitted before the server answers ---
    tcp_packet(C, 40102, S, 80, "S",  ts=T + 10.0, seq=2000, ack=0),     # 4 SYN
    tcp_packet(C, 40102, S, 80, "S",  ts=T + 11.0, seq=2000, ack=0),     # 5 SYN retransmit
    tcp_packet(S, 80, C, 40102, "SA", ts=T + 12.0, seq=8000, ack=2001),  # 6 SYN/ACK
    tcp_packet(C, 40102, S, 80, "A",  ts=T + 13.0, seq=2001, ack=8001),  # 7 ACK
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")