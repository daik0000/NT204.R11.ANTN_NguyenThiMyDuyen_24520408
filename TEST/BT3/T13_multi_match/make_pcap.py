"""Rebuild input.pcap for T13 (several matches on one packet). Deterministic: fixed IPs, ports, seq/ack and timestamps.
A complete handshake first, so that the flow is ESTABLISHED when the request arrives; then one request:
  10.0.0.5:52133 -> 192.168.1.20:80   GET /../../etc/passwd HTTP/1.1"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

T = 1700000000.0
CLIENT, SERVER = "10.0.0.5", "192.168.1.20"
REQUEST = b"GET /../../etc/passwd HTTP/1.1\r\nHost: t13.example\r\n\r\n"

PACKETS = [
    tcp_packet(CLIENT, 52133, SERVER, 80, "S",  ts=T + 0.0, seq=1000, ack=0),                        # 1 SYN
    tcp_packet(SERVER, 80, CLIENT, 52133, "SA", ts=T + 0.1, seq=7000, ack=1001),                     # 2 SYN/ACK
    tcp_packet(CLIENT, 52133, SERVER, 80, "A",  ts=T + 0.2, seq=1001, ack=7001),                     # 3 ACK: the flow is now ESTABLISHED
    tcp_packet(CLIENT, 52133, SERVER, 80, "PA", ts=T + 0.3, seq=1001, ack=7001, payload=REQUEST),    # 4 the request
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")
