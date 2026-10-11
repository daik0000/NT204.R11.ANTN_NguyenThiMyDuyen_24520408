"""Rebuild input.pcap for T05 (normalization). Deterministic: pcap_builder fixes MACs, the script fixes IPs, ports, seq, DNS ids and timestamps.
The synthetic half of T05 (events that cannot come from a pcap) lives in test_t05_normalization.py."""
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, udp_packet, write_pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def http_request(ts, sport, request_line, *headers):
    payload = ("\r\n".join([request_line, *headers]) + "\r\n\r\n").encode("ascii")
    return tcp_packet(CLIENT, sport, SERVER, 80, "PA", ts=ts, seq=1000, ack=2000, payload=payload)


QNAME = "WWW.Example.COM."

PACKETS = [
    # 1) Upper/mixed-case header names, mixed-case Host, a duplicated header (X-Tag twice, different case),
    #    percent-encoding written in lower case, and a '/../' that must NOT be collapsed
    http_request(1700000000.0, 40041, "GET /dir%2fsub/../x%2e?Q=%2f HTTP/1.1",
                 "HOST: WwW.ExAmPlE.CoM", "User-AGENT: Test/1.0", "ACCEPT-language: en", "X-Tag: a", "x-tag: b"),
    # 2) DNS query for a mixed-case name with a trailing dot
    udp_packet(CLIENT, 53001, SERVER, 53, ts=1700000001.0,
               payload=bytes(DNS(id=0x1001, rd=1, qd=DNSQR(qname=QNAME, qtype="A")))),
    # 3) DNS response: CNAME (its data is a domain name -> lower-cased) and an A record (its data is an address -> untouched)
    udp_packet(SERVER, 53, CLIENT, 53001, ts=1700000002.0,
               payload=bytes(DNS(id=0x1001, qr=1, aa=1, rd=1, ra=1, ancount=2, qd=DNSQR(qname=QNAME, qtype="A"),
                                 an=DNSRR(rrname=QNAME, type="CNAME", rdata="Edge.CDN-Example.NET.")
                                 / DNSRR(rrname="Edge.CDN-Example.NET.", type="A", rdata="192.0.2.7")))),
    # 4) Variant: a request that is already clean (lower-case headers, canonical path) -> nothing to normalize
    http_request(1700000003.0, 40042, "GET /index.html HTTP/1.1", "host: example.com", "user-agent: test"),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")