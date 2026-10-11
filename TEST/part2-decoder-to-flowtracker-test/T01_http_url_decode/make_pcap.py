"""Rebuild input.pcap for T01 (HTTP URL / form-urlencoded decoding). Deterministic: pcap_builder fixes MACs, the script fixes IPs, ports, seq and timestamps."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def http_request(ts, sport, *lines, body=""):
    """One PSH/ACK segment carrying a full HTTP request to port 80 (CRLF line endings, blank line before the body)."""
    payload = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("ascii")
    return tcp_packet(CLIENT, sport, SERVER, 80, "PA", ts=ts, seq=1000, ack=2000, payload=payload)


FORM_BODY = "user=a%40b.com&note=hello+world"

PACKETS = [
    # 1) The example from the assignment + a UTF-8 byte sequence (%C3%A9 = é)
    http_request(1700000000.0, 40001,
                 "GET /search?q=%27%20OR%201%3D1&name=caf%C3%A9 HTTP/1.1", "Host: example.com"),
    # 2) application/x-www-form-urlencoded body: %40 -> @, '+' -> space
    http_request(1700000001.0, 40002,
                 "POST /login HTTP/1.1", "Host: example.com",
                 "Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(FORM_BODY)}",
                 body=FORM_BODY),
    # 3) Variant: '+' in the PATH stays '+', '+' in the QUERY becomes a space, %20 in the path is decoded
    http_request(1700000002.0, 40003,
                 "GET /a+b/c%20d?x=1+2 HTTP/1.1", "Host: example.com"),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")