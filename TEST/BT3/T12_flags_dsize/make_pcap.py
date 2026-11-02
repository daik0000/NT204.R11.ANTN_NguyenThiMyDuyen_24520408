"""Rebuild input.pcap and variants.pcap for T12 (flags and dsize). Deterministic: fixed IPs, ports, seq/ack and timestamps.

input.pcap     a TCP session to port 9003 (no parser, so the payload is raw bytes):
               p1 SYN, p2 SYN/ACK, p3 ACK, p4 PSH/ACK with the 10 bytes 0123456789, p5 FIN/ACK
variants.pcap  the same five TCP packets followed by p6, a UDP datagram to port 9003 with the same 10 bytes"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

T = 1700000000.0
C, S = "10.0.0.1", "10.0.0.2"
DATA = b"0123456789"

PACKETS = [
    tcp_packet(C, 40012, S, 9003, "S",  ts=T + 0.0, seq=1000, ack=0),                       # p1 SYN
    tcp_packet(S, 9003, C, 40012, "SA", ts=T + 0.1, seq=7000, ack=1001),                    # p2 SYN/ACK
    tcp_packet(C, 40012, S, 9003, "A",  ts=T + 0.2, seq=1001, ack=7001),                    # p3 ACK
    tcp_packet(C, 40012, S, 9003, "PA", ts=T + 0.3, seq=1001, ack=7001, payload=DATA),      # p4 PSH/ACK, 10 bytes
    tcp_packet(C, 40012, S, 9003, "FA", ts=T + 0.4, seq=1011, ack=7001),                    # p5 FIN/ACK
]

VARIANT_PACKETS = PACKETS + [
    udp_packet(C, 40013, S, 9003, ts=T + 10.0, payload=DATA),                               # p6 UDP, 10 bytes
]

if __name__ == "__main__":
    for name, packets in (("input.pcap", PACKETS), ("variants.pcap", VARIANT_PACKETS)):
        out = write_pcap(packets, HERE / name)
        print(f"wrote {out} ({len(packets)} packets)")
