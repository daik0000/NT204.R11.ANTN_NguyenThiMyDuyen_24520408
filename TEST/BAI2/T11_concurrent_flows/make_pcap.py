"""Rebuild input.pcap for T11 (concurrent flows). Deterministic: fixed IPs, ports, seq/ack; packet i is sent at T + 0.25 * (i - 1).
Five interleaved flows:
  F1 TCP 10.0.0.1:40401 -> 10.0.0.2:9000   (reference)
  F2 TCP 10.0.0.1:40402 -> 10.0.0.2:9000   (same client IP, different source port)
  F3 TCP 10.0.0.1:40401 -> 10.0.0.2:9001   (same IPs and source port, different destination port)
  F4 TCP 10.0.0.3:40401 -> 10.0.0.4:9000   (different IPs entirely, handshake never completes)
  F5 UDP 10.0.0.1:40401 -> 10.0.0.2:9000   (same IPs/ports as F1 but UDP: protocol is part of the flow key)"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

T = 1700000000.0
A, B, C3, D = "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"


def ts(packet_id):
    return T + 0.25 * (packet_id - 1)


PACKETS = [
    tcp_packet(A, 40401, B, 9000, "S",  ts=ts(1),  seq=1000, ack=0),        # 1  F1 SYN
    tcp_packet(A, 40402, B, 9000, "S",  ts=ts(2),  seq=2000, ack=0),        # 2  F2 SYN
    tcp_packet(A, 40401, B, 9001, "S",  ts=ts(3),  seq=3000, ack=0),        # 3  F3 SYN
    tcp_packet(C3, 40401, D, 9000, "S", ts=ts(4),  seq=4000, ack=0),        # 4  F4 SYN
    tcp_packet(B, 9000, A, 40401, "SA", ts=ts(5),  seq=7000, ack=1001),     # 5  F1 SYN/ACK
    udp_packet(A, 40401, B, 9000,       ts=ts(6),  payload=b"ping"),        # 6  F5 request
    tcp_packet(B, 9000, A, 40402, "SA", ts=ts(7),  seq=8000, ack=2001),     # 7  F2 SYN/ACK
    tcp_packet(B, 9001, A, 40401, "SA", ts=ts(8),  seq=9000, ack=3001),     # 8  F3 SYN/ACK
    tcp_packet(D, 9000, C3, 40401, "SA", ts=ts(9), seq=6000, ack=4001),     # 9  F4 SYN/ACK
    udp_packet(B, 9000, A, 40401,       ts=ts(10), payload=b"pong"),        # 10 F5 reply
    tcp_packet(A, 40401, B, 9000, "A",  ts=ts(11), seq=1001, ack=7001),     # 11 F1 ACK
    tcp_packet(A, 40402, B, 9000, "A",  ts=ts(12), seq=2001, ack=8001),     # 12 F2 ACK
    tcp_packet(A, 40401, B, 9001, "A",  ts=ts(13), seq=3001, ack=9001),     # 13 F3 ACK
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")