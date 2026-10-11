"""Rebuild input.pcap for T03 (SMTP MIME Base64 / Quoted-Printable). Deterministic: pcap_builder fixes MACs, the script fixes IPs, ports, seq and timestamps."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "helpers"))   # TEST/helpers
from pcap_builder import tcp_packet, write_pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
END_OF_DATA = "\r\n.\r\n"          # SMTP end-of-data marker, must not end up in the decoded text


def smtp_data(ts, client_port, transfer_encoding_line, body):
    """One PSH/ACK segment carrying MIME headers + blank line + body to port 25.
    The packet must START with a header line, because the parser has no session state."""
    headers = ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", transfer_encoding_line]
    payload = ("\r\n".join(headers) + "\r\n\r\n" + body + END_OF_DATA).encode("ascii")
    return tcp_packet(CLIENT, client_port, SERVER, 25, "PA", ts=ts, seq=1000, ack=2000, payload=payload)


PACKETS = [
    # 1) Valid Base64: "Q2Fm"="Caf", "w6kg"=C3 A9 20="é ", "SURT"="IDS"  -> "Café IDS"
    smtp_data(1700000000.0, 40021, "Content-Transfer-Encoding: base64", "Q2Fmw6kgSURT"),
    # 2) Quoted-Printable: =C3=A0 -> "à", =C3=A9 -> "é", =3D -> "=", soft line break "=\r\n" -> removed
    smtp_data(1700000001.0, 40022, "Content-Transfer-Encoding: quoted-printable",
              "Xin ch=C3=A0o caf=C3=A9, 1+1=3D2, soft=\r\nbreak"),
    # 3) Variant: damaged Base64 (a '!' inside and missing padding) -> cleaned, PARTIAL
    smtp_data(1700000002.0, 40023, "Content-Transfer-Encoding: base64", "SGVs!bG8"),
    # 4) Variant: Base64 that cannot be decoded at all (a single leftover character) -> FAILED, raw text kept
    smtp_data(1700000003.0, 40024, "Content-Transfer-Encoding: base64", "A"),
    # 5) Variant: header written as "  BASE64 " (upper case, extra spaces) must still be recognised
    #    (and proves the packets after the damaged ones are still processed)
    smtp_data(1700000004.0, 40025, "Content-Transfer-Encoding:  BASE64 ", "SGVsbG8gV29ybGQ="),
]

if __name__ == "__main__":
    out = write_pcap(PACKETS, HERE / "input.pcap")
    print(f"wrote {out} ({len(PACKETS)} packets)")