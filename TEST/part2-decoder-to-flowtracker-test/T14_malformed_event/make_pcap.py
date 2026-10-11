"""Rebuild input.pcap for T14 (malformed / unsupported packets). Deterministic: pcap_builder fixes the MACs,
this script fixes IPs, ports and timestamps. Only what can really be on the wire is here; events with an
out-of-range port, a NaN timestamp or a missing src_ip cannot come from a pcap and live in test_t14_malformed_event.py."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import _frame, tcp_packet, write_pcap
from scapy.all import ARP, ICMP, Ether, Raw

T = 1700000000.0
C, S = "10.0.0.1", "10.0.0.2"


def _at(pkt, ts):
    pkt.time = ts
    return pkt


_full = bytes(tcp_packet(C, 40701, S, 80, "S", ts=T, seq=1000, ack=0))        # 54 bytes: Ethernet + IPv4 + TCP
_eth = _full[:12]                                                              # destination + source MAC

PACKETS = [
    # 1) cut inside the IPv4 header: Ethernet (14) + only 6 bytes of IP -> malformed network layer
    _at(Ether(_eth + b"\x08\x00") / Raw(load=_full[14:20]), T + 0.0),
    # 2) ICMP echo request: IPv4 but an unsupported transport protocol
    _at(_frame(C, S) / ICMP(type=8, id=1, seq=1), T + 1.0),
    # 3) ARP request: not IPv4 at all
    _at(Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01") / ARP(op=1, psrc=C, pdst=S), T + 2.0),
    # 4) cut inside the TCP header: Ethernet + full IPv4 header + only 10 bytes of TCP
    _at(Ether(_eth + b"\x08\x00") / Raw(load=_full[14:44]), T + 3.0),
    # 5) a perfectly valid SYN at the end: it must still create a flow
    tcp_packet(C, 40701, S, 80, "S", ts=T + 4.0, seq=2000, ack=0),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")