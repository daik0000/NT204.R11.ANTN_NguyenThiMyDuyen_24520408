import os

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def _mac_for(ip):
    """Fixed MAC derived from IPv4: same IP -> always same MAC (02: = locally administered)."""
    return "02:00:" + ":".join(f"{int(o):02x}" for o in ip.split("."))


def _frame(src, dst):
    return Ether(src=_mac_for(src), dst=_mac_for(dst)) / IP(src=src, dst=dst)


def tcp_packet(src, sport, dst, dport, flags, *, ts, seq=1000, ack=0, payload=b""):
    """Build a TCP packet (Ethernet/IPv4). `ts` is required so the timestamp is always set by the test writer."""
    pkt = _frame(src, dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        pkt = pkt / payload
    pkt.time = ts
    return pkt


def udp_packet(src, sport, dst, dport, *, ts, payload=b""):
    """Build a UDP packet (Ethernet/IPv4)."""
    pkt = _frame(src, dst) / UDP(sport=sport, dport=dport)
    if payload:
        pkt = pkt / payload
    pkt.time = ts
    return pkt


def write_pcap(packets, path):
    """Write a list of packets to a pcap file, auto-creating directories; return the absolute path written."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wrpcap(path, packets)
    return path