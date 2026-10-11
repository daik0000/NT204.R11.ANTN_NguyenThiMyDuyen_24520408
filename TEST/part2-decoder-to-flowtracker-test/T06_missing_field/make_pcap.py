"""Rebuild input.pcap for T06 (missing fields). Deterministic: pcap_builder fixes MACs, the script fixes IPs, ports, seq and timestamps.
Only the packets that really exist on the wire are here (TCP without payload); events that miss fields
(no app_fields, no flags, wrong types...) cannot come from a pcap and are built in test_t06_missing_field.py."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"

PACKETS = [
    # 1) TCP SYN with no payload at all: there is no application layer to fill app_fields from
    tcp_packet(CLIENT, 40051, SERVER, 80, "S", ts=1700000000.0, seq=5000, ack=0),
    # 2) Variant: a pure ACK (no payload) of another connection
    tcp_packet(CLIENT, 40052, SERVER, 80, "A", ts=1700000001.0, seq=5001, ack=9001),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")