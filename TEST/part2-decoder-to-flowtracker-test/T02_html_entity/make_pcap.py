"""Rebuild input.pcap for T02 (HTML entity decoding). Deterministic: pcap_builder fixes MACs, the script fixes IPs, ports, seq and timestamps."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def http_message(ts, *, src, sport, dst, dport, lines, body=""):
    """One PSH/ACK segment with a full HTTP message (CRLF line endings, blank line before the body)."""
    payload = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("ascii")
    return tcp_packet(src, sport, dst, dport, "PA", ts=ts, seq=1000, ack=2000, payload=payload)


def response(ts, client_port, body):
    """HTTP 200 response (server -> client) with an HTML body."""
    return http_message(ts, src=SERVER, sport=80, dst=CLIENT, dport=client_port, body=body, lines=[
        "HTTP/1.1 200 OK", "Content-Type: text/html; charset=utf-8", f"Content-Length: {len(body)}"])


# 1) Entities in an HTML body: &lt; &gt; named, &#x27; numeric (hex)
BODY_1 = "&lt;script&gt;alert(1)&lt;/script&gt; &#x27;ok&#x27;"

# 2) Form body: percent-decoding must happen BEFORE entity decoding
#    c=%26lt%3Bb%26gt%3B  -> "&lt;b&gt;" -> "<b>"
#    e=%26amp%3Blt%3B     -> "&amp;lt;"  -> "&lt;"   (entities are decoded only ONCE)
FORM_BODY = "c=%26lt%3Bb%26gt%3B&e=%26amp%3Blt%3B&n=1"

# 4) Variant: several entities in one body + a double-encoded one
BODY_4 = "1 &lt; 2 &amp;&amp; 3 &gt; 2 &amp;lt;"

PACKETS = [
    response(1700000000.0, 40011, BODY_1),
    http_message(1700000001.0, src=CLIENT, sport=40012, dst=SERVER, dport=80, body=FORM_BODY, lines=[
        "POST /comment HTTP/1.1", "Host: example.com",
        "Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(FORM_BODY)}"]),
    # 3) '&copy=2' inside a URI must NOT be turned into the copyright sign (HTML5 accepts '&copy' without ';')
    http_message(1700000002.0, src=CLIENT, sport=40013, dst=SERVER, dport=80,
                 lines=["GET /page?a=1&copy=2 HTTP/1.1", "Host: example.com"]),
    response(1700000003.0, 40014, BODY_4),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")