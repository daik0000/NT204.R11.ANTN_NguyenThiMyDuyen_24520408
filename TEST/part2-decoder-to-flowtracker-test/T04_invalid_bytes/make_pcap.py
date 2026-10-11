"""Rebuild input.pcap for T04 (invalid UTF-8 bytes). Deterministic: pcap_builder fixes MACs, the script fixes IPs, ports, seq and timestamps.
Payloads are built from BYTES on purpose: the bodies contain 0xFF / 0xFE / 0xC3 which are not valid UTF-8."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def http_request(ts, sport, request_line, body=None):
    """One PSH/ACK segment with a full HTTP request. A body (bytes) is sent as text/plain; charset=utf-8."""
    lines = [request_line, "Host: example.com"]
    if body is not None:
        lines += ["Content-Type: text/plain; charset=utf-8", f"Content-Length: {len(body)}"]
    payload = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + (body or b"")
    return tcp_packet(CLIENT, sport, SERVER, 80, "PA", ts=ts, seq=1000, ack=2000, payload=payload)


PACKETS = [
    # 1) Body with two bad bytes in the middle: "abc" + FF FE + "def"  -> 2 invalid bytes, first at offset 3
    http_request(1700000000.0, 40031, "POST /upload HTTP/1.1", b"abc\xff\xfedef"),
    # 2) URI with %FF: "/img?name=ab" is 12 bytes, so the bad byte is at offset 12
    http_request(1700000001.0, 40032, "GET /img?name=ab%FFcd HTTP/1.1"),
    # 3) Variant: a multi-byte character cut in half ("é" is C3 A9, only C3 is present) -> 1 bad byte at offset 3
    http_request(1700000002.0, 40033, "POST /upload HTTP/1.1", b"caf\xc3"),
    # 4) Variant: one stray NUL must NOT hide the bad byte (1 NUL in 5 bytes is below the 30% 'binary' threshold)
    http_request(1700000003.0, 40034, "POST /upload HTTP/1.1", b"a\x00b\xffc"),
    # 5) A normal packet at the end: the program must keep going and decode it as OK
    http_request(1700000004.0, 40035, "POST /upload HTTP/1.1", b"hello"),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")