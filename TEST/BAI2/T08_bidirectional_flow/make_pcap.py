"""Rebuild input.pcap for T08 (bidirectional flow). Deterministic: fixed IPs, ports, seq/ack and timestamps.
Connection A = full handshake + HTTP request/response. Connection B = capture starts at the server's response."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

C, S = "10.0.0.1", "10.0.0.2"
T = 1700000000.0

REQ = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"        # 47 bytes
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"            # 43 bytes

PACKETS = [
    # --- connection A (client port 40201) ---
    tcp_packet(C, 40201, S, 80, "S",  ts=T + 0.0, seq=1000, ack=0),                          # 1 SYN
    tcp_packet(S, 80, C, 40201, "SA", ts=T + 1.0, seq=7000, ack=1001),                       # 2 SYN/ACK
    tcp_packet(C, 40201, S, 80, "A",  ts=T + 2.0, seq=1001, ack=7001),                       # 3 ACK
    tcp_packet(C, 40201, S, 80, "PA", ts=T + 3.0, seq=1001, ack=7001, payload=REQ),          # 4 request
    tcp_packet(S, 80, C, 40201, "PA", ts=T + 4.0, seq=7001, ack=1048, payload=RESP),         # 5 response
    tcp_packet(C, 40201, S, 80, "A",  ts=T + 5.0, seq=1048, ack=7044),                       # 6 ACK of response
    # --- connection B (client port 40202): the capture begins with the server's packet ---
    tcp_packet(S, 80, C, 40202, "PA", ts=T + 10.0, seq=9000, ack=3000, payload=RESP),        # 7 response first
    tcp_packet(C, 40202, S, 80, "A",  ts=T + 11.0, seq=3000, ack=9043),                      # 8 ACK
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")