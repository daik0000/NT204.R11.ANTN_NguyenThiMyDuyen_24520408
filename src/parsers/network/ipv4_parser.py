from typing import Dict, Any
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from src.utils.safe import safe_parse

IPV4_ETHERTYPE = 0x0800

@safe_parse
def parse_ipv4(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Decodes raw network bytes into an IPv4 normalized dictionary matching the IDSEvent schema.
    Acts as the isolation boundary: Scapy objects are created and destroyed here.
    Includes heuristic checks to differentiate between Ethernet frames and raw IP captures.
    """
    pkt = Ether(raw_bytes)
    
    # 1. Check if it's a valid Ethernet frame encapsulating IPv4
    if pkt.type == IPV4_ETHERTYPE:
        # If Ethertype says IPv4 but Scapy couldn't dissect the IP layer, the header is severely corrupted.
        # -> Raise an error to let @safe_parse catch it and mark it as MALFORMED.
        if not pkt.haslayer(IP):
            raise ValueError("Ethertype indicates IPv4, but IP layer dissection failed (malformed header).")
            
    # 2. Heuristic for Raw IP Capture (e.g., loopback, tun/tap interfaces without L2 Ethernet headers)
    # Check if the first nibble (4 bits) is equal to 4 (IPv4 version indicator)
    elif len(raw_bytes) > 0 and (raw_bytes[0] >> 4) == 4:
        pkt = IP(raw_bytes)
        
    # 3. Valid packet but not IPv4 (e.g., ARP, IPv6, 802.1Q VLAN tags)
    else:
        return {"status": "UNKNOWN", "layer": "IPv4"}

    # Final safety check before extracting fields
    if not pkt.haslayer(IP):
        return {"status": "UNKNOWN", "layer": "IPv4"}

    ip_layer = pkt[IP]
    
    return {
        "status": "OK",
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "network_protocol": "IPv4",
        
        # Group network-specific fields exactly as required by the IDSEvent schema
        "network_fields": {
            "ttl": ip_layer.ttl,
            "header_length": ip_layer.ihl * 4,
            "ip_proto_number": ip_layer.proto,  # 6 -> TCP, 17 -> UDP
        },
        
        # Extract the L4 payload using .original to preserve the exact raw bytes.
        # Calling bytes() on a sub-layer triggers Scapy's .build() which alters malformed packets.
        "transport_payload": ip_layer.payload.original 
    }

if __name__ == "__main__":
    import logging
    from scapy.layers.inet import UDP
    
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST IPV4 PARSER ===")
    
    dummy_pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8", ttl=64) / UDP(sport=12345, dport=53) / b"Test Payload"
    
    raw_bytes = bytes(dummy_pkt)
    
    result = parse_ipv4(raw_bytes)
    
    print(result)