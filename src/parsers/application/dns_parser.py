import struct
from typing import Dict, Any
from scapy.layers.dns import DNS, DNSQR, DNSRR
from src.utils.safe import safe_parse

# Mapping of common DNS record types from int to string for readable JSON logs
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY"
}

def _get_dns_type(type_val: int) -> str:
    """Helper mapping int to string; if unknown, keep format UNKNOWN(int)"""
    return DNS_TYPES.get(type_val, f"UNKNOWN({type_val})")

def _looks_like_dns_header(raw_bytes: bytes) -> bool:
    """
    Validates the bitfield structure of the DNS header before trusting Scapy's dissection.
    Prevents Scapy from force-fitting garbage data into a fake DNS packet.
    """
    try:
        _, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", raw_bytes[:12])
        opcode = (flags >> 11) & 0xF
        z_reserved = (flags >> 4) & 0x7
        # Only accept standard opcodes (0,1,2), Z-reserved must be 0, and question count must be reasonable
        return opcode in (0, 1, 2) and z_reserved == 0 and qdcount <= 100
    except struct.error:
        return False

@safe_parse
def parse_dns(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses an L7 payload into a DNS query or response.
    """
    if not raw_bytes or len(raw_bytes) < 12:
        raise ValueError(f"Payload too short to be a valid DNS packet ({len(raw_bytes)} bytes).")

    # Bitwise sanity-check 
    if not _looks_like_dns_header(raw_bytes):
        raise ValueError("Payload does not have a valid DNS header structure (unusual opcode/reserved bits).")

    pkt = DNS(raw_bytes)

    app_fields = {
        "transaction_id": pkt.id,
        "type": "response" if pkt.qr == 1 else "query",
        "rcode": pkt.rcode,
        "queries": [],
        "answers": []
    }

    # 1. Parse Question Section
    if pkt.qdcount > 0 and pkt.qd is not None:
        current_q = pkt.qd
        count = 0
        while current_q and count < pkt.qdcount:
            if isinstance(current_q, DNSQR):
                qname = current_q.qname.decode('utf-8', errors='ignore').rstrip('.') if current_q.qname else ""
                app_fields["queries"].append({
                    "name": qname,
                    "qtype": _get_dns_type(current_q.qtype)
                })
            current_q = current_q.payload
            count += 1

    # 2. Parse Answer Section
    if pkt.qr == 1 and pkt.ancount > 0 and pkt.an is not None:
        current_a = pkt.an
        count = 0
        while current_a and count < pkt.ancount:
            if isinstance(current_a, DNSRR):
                rrname = current_a.rrname.decode('utf-8', errors='ignore').rstrip('.') if current_a.rrname else ""
                rdata = current_a.rdata
                
                if isinstance(rdata, list):
                    rdata_str = " ".join([b.decode('utf-8', errors='ignore') if isinstance(b, bytes) else str(b) for b in rdata])
                elif isinstance(rdata, bytes):
                    rdata_str = rdata.decode('utf-8', errors='ignore')
                else:
                    rdata_str = str(rdata)
                    
                app_fields["answers"].append({
                    "name": rrname,
                    "type": _get_dns_type(current_a.type),
                    "data": rdata_str.rstrip('.')
                })
            current_a = current_a.payload
            count += 1

    return {
        "status": "OK",
        "app_protocol": "DNS",
        "app_fields": app_fields
    }

if __name__ == "__main__":
    import pprint
    import logging
    
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST DNS PARSER ===")
    
    print("\n--- Valid DNS Response ---")
    resp_pkt = DNS(id=0x1234, qr=1, aa=1, rcode=0, 
                   qd=DNSQR(qname="example.com", qtype=1),
                   an=DNSRR(rrname="example.com", type=1, rdata="93.184.216.34"))
    pprint.pprint(parse_dns(bytes(resp_pkt)))
    
    print("\n--- Fake DNS (Garbage Bytes) ---")
    # Garbage packet with exactly 12 bytes but invalid opcode/Z-reserved
    fake_payload = b"\xff\xff\xff\xff\x00\x01\x00\x00\x00\x00\x00\x00"
    pprint.pprint(parse_dns(fake_payload))