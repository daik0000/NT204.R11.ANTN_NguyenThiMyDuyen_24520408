"""Rebuild input.pcap and variants.pcap for T08 (flow established). Deterministic: fixed IPs, ports, seq/ack and timestamps.

input.pcap
  flow 1  complete TCP session to port 80:  SYN, SYN/ACK, ACK, "GET /", "HTTP/1.1 200 OK"
  flow 2  MIDSTREAM: only the request "GET /" (no handshake seen)
  flow 3  MIDSTREAM, captured from the server side: the first packet is the response from port 80
  flow 4  UDP DNS: query, then response
variants.pcap
  flow X  SYN, SYN/ACK, ACK, FIN/ACK from the client (CLOSING), FIN/ACK from the server (CLOSED), a late ACK
  flow Y  SYN, SYN/ACK, ACK, RST/ACK from the server (RESET)"""
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

T = 1700000000.0
SERVER = "10.0.0.2"
REQUEST = b"GET / HTTP/1.1\r\nHost: t08.example\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
DNS_QUERY = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="t08.example")))
DNS_RESPONSE = bytes(DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="t08.example"),
                         an=DNSRR(rrname="t08.example", ttl=60, rdata="93.184.216.34")))

C1, C2, C3 = "10.0.0.1", "10.0.0.3", "10.0.0.4"

PACKETS = [
    # --- flow 1: complete session (client 10.0.0.1:40101) ---
    tcp_packet(C1, 40101, SERVER, 80, "S",  ts=T + 0.0, seq=1000, ack=0),                           # 1  SYN
    tcp_packet(SERVER, 80, C1, 40101, "SA", ts=T + 0.1, seq=7000, ack=1001),                        # 2  SYN/ACK
    tcp_packet(C1, 40101, SERVER, 80, "A",  ts=T + 0.2, seq=1001, ack=7001),                        # 3  ACK
    tcp_packet(C1, 40101, SERVER, 80, "PA", ts=T + 0.3, seq=1001, ack=7001, payload=REQUEST),       # 4  GET /
    tcp_packet(SERVER, 80, C1, 40101, "PA", ts=T + 0.4, seq=7001, ack=1001 + len(REQUEST), payload=RESPONSE),   # 5  200 OK
    # --- flow 2: midstream, only the request (client 10.0.0.3:40102) ---
    tcp_packet(C2, 40102, SERVER, 80, "PA", ts=T + 10.0, seq=5001, ack=9001, payload=REQUEST),      # 6  GET /
    # --- flow 3: midstream, first packet is the server's response (client 10.0.0.4:40103) ---
    tcp_packet(SERVER, 80, C3, 40103, "PA", ts=T + 20.0, seq=9001, ack=5001, payload=RESPONSE),     # 7  200 OK from port 80
    # --- flow 4: UDP DNS (client 10.0.0.1:5353) ---
    udp_packet(C1, 5353, SERVER, 53, ts=T + 30.0, payload=DNS_QUERY),                               # 8  query
    udp_packet(SERVER, 53, C1, 5353, ts=T + 30.1, payload=DNS_RESPONSE),                            # 9  response
]

VARIANT_PACKETS = [
    # --- flow X (client 10.0.0.1:40201): closes cleanly ---
    tcp_packet(C1, 40201, SERVER, 80, "S",  ts=T + 100.0, seq=1000, ack=0),                         # 1
    tcp_packet(SERVER, 80, C1, 40201, "SA", ts=T + 100.1, seq=7000, ack=1001),                      # 2
    tcp_packet(C1, 40201, SERVER, 80, "A",  ts=T + 100.2, seq=1001, ack=7001),                      # 3  ESTABLISHED
    tcp_packet(C1, 40201, SERVER, 80, "FA", ts=T + 100.3, seq=1001, ack=7001),                      # 4  client FIN -> CLOSING
    tcp_packet(SERVER, 80, C1, 40201, "FA", ts=T + 100.4, seq=7001, ack=1002),                      # 5  server FIN -> CLOSED
    tcp_packet(C1, 40201, SERVER, 80, "A",  ts=T + 100.5, seq=1002, ack=7002),                      # 6  late ACK, state stays CLOSED
    # --- flow Y (client 10.0.0.3:40202): reset ---
    tcp_packet(C2, 40202, SERVER, 80, "S",  ts=T + 110.0, seq=2000, ack=0),                         # 7
    tcp_packet(SERVER, 80, C2, 40202, "SA", ts=T + 110.1, seq=8000, ack=2001),                      # 8
    tcp_packet(C2, 40202, SERVER, 80, "A",  ts=T + 110.2, seq=2001, ack=8001),                      # 9  ESTABLISHED
    tcp_packet(SERVER, 80, C2, 40202, "RA", ts=T + 110.3, seq=8001, ack=2001),                      # 10 RST/ACK -> RESET
]

if __name__ == "__main__":
    for name, packets in (("input.pcap", PACKETS), ("variants.pcap", VARIANT_PACKETS)):
        out = write_pcap(packets, HERE / name)
        print(f"wrote {out} ({len(packets)} packets)")
