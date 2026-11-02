"""Rebuild input.pcap and variants.pcap for T14 (Detection Event). Deterministic: fixed IPs, ports, seq/ack and timestamps.

input.pcap     handshake, then the request  10.0.0.5:52133 -> 192.168.1.20:80  GET /../../etc/passwd HTTP/1.1
variants.pcap  the same four packets, then a DNS query and its response (UDP 10.0.0.5:5353 <-> 192.168.1.20:53)"""
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

T = 1700000000.0
CLIENT, SERVER = "10.0.0.5", "192.168.1.20"
REQUEST = b"GET /../../etc/passwd HTTP/1.1\r\nHost: t14.example\r\n\r\n"
DNS_QUERY = bytes(DNS(id=0x4242, rd=1, qd=DNSQR(qname="t14.example")))
DNS_RESPONSE = bytes(DNS(id=0x4242, qr=1, rd=1, ra=1, qd=DNSQR(qname="t14.example"),
                         an=DNSRR(rrname="t14.example", ttl=60, rdata="93.184.216.34")))

PACKETS = [
    tcp_packet(CLIENT, 52133, SERVER, 80, "S",  ts=T + 0.0, seq=1000, ack=0),                        # 1 SYN
    tcp_packet(SERVER, 80, CLIENT, 52133, "SA", ts=T + 0.1, seq=7000, ack=1001),                     # 2 SYN/ACK
    tcp_packet(CLIENT, 52133, SERVER, 80, "A",  ts=T + 0.2, seq=1001, ack=7001),                     # 3 ACK
    tcp_packet(CLIENT, 52133, SERVER, 80, "PA", ts=T + 0.3, seq=1001, ack=7001, payload=REQUEST),    # 4 the request
]

VARIANT_PACKETS = PACKETS + [
    udp_packet(CLIENT, 5353, SERVER, 53, ts=T + 10.0, payload=DNS_QUERY),                            # 5 DNS query
    udp_packet(SERVER, 53, CLIENT, 5353, ts=T + 10.1, payload=DNS_RESPONSE),                         # 6 DNS response
]

if __name__ == "__main__":
    for name, packets in (("input.pcap", PACKETS), ("variants.pcap", VARIANT_PACKETS)):
        out = write_pcap(packets, HERE / name)
        print(f"wrote {out} ({len(packets)} packets)")
