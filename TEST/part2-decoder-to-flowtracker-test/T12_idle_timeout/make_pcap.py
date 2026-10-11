"""Rebuild input.pcap for T12 (idle timeout). Pair it with settings.yaml in this folder
(udp_idle_timeout_sec=5, tcp_idle_timeout_sec=5, tcp_handshake_timeout_sec=3, sweep_interval_sec=1).
Timeouts use event time (packet timestamps), so nothing sleeps. Deterministic: fixed IPs, ports, seq/ack, timestamps."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

T = 1700000000.0
A, B, X = "10.0.0.1", "10.0.0.2", "10.0.0.9"

PACKETS = [
    udp_packet(A, 50001, B, 9000, ts=T + 0.0, payload=b"hi"),                    # 1  U  UDP flow, request
    tcp_packet(A, 40501, B, 9100, "S",  ts=T + 0.5,  seq=1000, ack=0),           # 2  E  SYN
    tcp_packet(A, 40502, B, 9200, "S",  ts=T + 0.75, seq=2000, ack=0),           # 3  H  SYN that is never answered
    udp_packet(B, 9000, A, 50001, ts=T + 1.0, payload=b"hi"),                    # 4  U  UDP flow, reply (last_seen = 1.0)
    tcp_packet(B, 9100, A, 40501, "SA", ts=T + 1.5,  seq=7000, ack=1001),        # 5  E  SYN/ACK
    tcp_packet(A, 40501, B, 9100, "A",  ts=T + 2.0,  seq=1001, ack=7001),        # 6  E  ACK (last_seen = 2.0)
    udp_packet(A, 50001, B, 9000, ts=T + 8.0, payload=b"hi"),                    # 7  U' same 5-tuple as U, after its timeout (8 - 1 = 7 > 5)
    tcp_packet(X, 50009, B, 9300, "S",  ts=T + 20.0, seq=3000, ack=0),           # 8  X  unrelated packet far in the future
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")