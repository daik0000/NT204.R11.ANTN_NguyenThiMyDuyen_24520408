"""Rebuild input.pcap and variants.pcap for T05 (direction). Deterministic: fixed IPs, ports, seq/ack and timestamps.

input.pcap     the three packets of the issue: forward, reverse, and a packet from another host.
variants.pcap  four packets for the fixed-port rules: forward, the exact reverse, and two packets that swap
               only the IPs or only the ports (a reversed packet swaps both)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

T = 1700000000.0
CLIENT, SERVER = "10.0.0.5", "192.168.1.20"

PACKETS = [
    tcp_packet(CLIENT, 52133, SERVER, 80, "S",  ts=T + 0.0, seq=1000, ack=0),        # 1 client -> server
    tcp_packet(SERVER, 80, CLIENT, 52133, "SA", ts=T + 1.0, seq=7000, ack=1001),     # 2 server -> client (reverse)
    tcp_packet("10.9.9.9", 52133, SERVER, 80, "S", ts=T + 2.0, seq=3000, ack=0),     # 3 another host -> server
]

VARIANT_PACKETS = [
    tcp_packet(CLIENT, 52133, SERVER, 80, "A",  ts=T + 10.0, seq=1, ack=1),          # v1 forward
    tcp_packet(SERVER, 80, CLIENT, 52133, "A",  ts=T + 11.0, seq=1, ack=1),          # v2 exact reverse: IPs and ports swapped
    tcp_packet(SERVER, 52133, CLIENT, 80, "A",  ts=T + 12.0, seq=1, ack=1),          # v3 only the IPs swapped, ports kept
    tcp_packet(CLIENT, 80, SERVER, 52133, "A",  ts=T + 13.0, seq=1, ack=1),          # v4 only the ports swapped, IPs kept
]

if __name__ == "__main__":
    for name, packets in (("input.pcap", PACKETS), ("variants.pcap", VARIANT_PACKETS)):
        out = write_pcap(packets, HERE / name)
        print(f"wrote {out} ({len(packets)} packets)")
