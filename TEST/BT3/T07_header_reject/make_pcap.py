"""Rebuild input.pcap and variants.pcap for T07 (header reject). Deterministic: fixed IPs, ports, seq/ack and timestamps.

input.pcap     the three packets of the issue, all carrying the payload "GET / HTTP/1.1":
               (a) the exact 5-tuple of the rule   (b) another destination IP, port 80   (c) destination port 8080
variants.pcap  four more ways to miss the header (the content would match every one of them):
               (d) another source IP  (e) UDP instead of TCP  (f) the reply direction  (g) a neighbouring destination IP"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

T = 1700000000.0
REQUEST = b"GET / HTTP/1.1\r\n\r\n"

PACKETS = [
    tcp_packet("10.0.0.5", 52133, "192.168.1.20", 80,   "PA", ts=T + 0.0, seq=1001, ack=7001, payload=REQUEST),   # a
    tcp_packet("10.0.0.5", 52134, "10.9.9.9",     80,   "PA", ts=T + 1.0, seq=1001, ack=7001, payload=REQUEST),   # b
    tcp_packet("10.0.0.5", 52135, "192.168.1.20", 8080, "PA", ts=T + 2.0, seq=1001, ack=7001, payload=REQUEST),   # c
]

VARIANT_PACKETS = [
    tcp_packet("10.9.9.9",     52136, "192.168.1.20", 80,    "PA", ts=T + 10.0, seq=1001, ack=7001, payload=REQUEST),   # d another source IP
    udp_packet("10.0.0.5",     52137, "192.168.1.20", 80,    ts=T + 11.0, payload=REQUEST),                             # e UDP, not TCP
    tcp_packet("192.168.1.20", 80,    "10.0.0.5",     52138, "PA", ts=T + 12.0, seq=7001, ack=1001, payload=REQUEST),   # f the reply direction
    tcp_packet("10.0.0.5",     52139, "192.168.1.21", 80,    "PA", ts=T + 13.0, seq=1001, ack=7001, payload=REQUEST),   # g 192.168.1.21, not .20
]

if __name__ == "__main__":
    for name, packets in (("input.pcap", PACKETS), ("variants.pcap", VARIANT_PACKETS)):
        out = write_pcap(packets, HERE / name)
        print(f"wrote {out} ({len(packets)} packets)")
