"""Rebuild input.pcap for T10 (UDP DNS query/response). Deterministic: fixed IPs, ports, DNS ids and timestamps.
Exchange 1 = A query answered with one A record. Exchange 2 (variant) = AAAA query answered NXDOMAIN with no answers."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import udp_packet, write_pcap
from scapy.layers.dns import DNS, DNSQR, DNSRR

C, S = "10.0.0.1", "10.0.0.53"
T = 1700000000.0

Q1, Q2 = "www.example.com.", "nonexistent.example.org."

PACKETS = [
    # --- exchange 1 (client port 53011) ---
    udp_packet(C, 53011, S, 53, ts=T + 0.0,
               payload=bytes(DNS(id=0x2001, rd=1, qd=DNSQR(qname=Q1, qtype="A")))),                    # 1 query
    udp_packet(S, 53, C, 53011, ts=T + 0.5,
               payload=bytes(DNS(id=0x2001, qr=1, aa=1, rd=1, ra=1, ancount=1, qd=DNSQR(qname=Q1, qtype="A"),
                                 an=DNSRR(rrname=Q1, type="A", ttl=300, rdata="93.184.216.34")))),     # 2 response
    # --- exchange 2 (client port 53012): NXDOMAIN ---
    udp_packet(C, 53012, S, 53, ts=T + 2.0,
               payload=bytes(DNS(id=0x2002, rd=1, qd=DNSQR(qname=Q2, qtype="AAAA")))),                 # 3 query
    udp_packet(S, 53, C, 53012, ts=T + 2.25,
               payload=bytes(DNS(id=0x2002, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=Q2, qtype="AAAA")))),  # 4 response
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")