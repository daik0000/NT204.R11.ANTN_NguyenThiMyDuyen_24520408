from typing import Dict, Any
from scapy.layers.inet import UDP
from scapy.packet import NoPayload
from src.utils.safe import safe_parse

# Minimum length of a standard UDP header is strictly 8 bytes
MIN_UDP_HEADER_LEN = 8

@safe_parse
def parse_udp(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Decodes the L4 transport payload into a UDP normalized dictionary.
    UDP is connectionless and stateless, so the extracted fields are minimal.
    Handles Ethernet padding anomalies by tracking length mismatches.
    """
    if len(raw_bytes) < MIN_UDP_HEADER_LEN:
        raise ValueError(
            f"Payload too short to be a valid UDP header "
            f"({len(raw_bytes)} bytes, minimum required is {MIN_UDP_HEADER_LEN})."
        )

    pkt = UDP(raw_bytes)
    udp_layer = pkt[UDP]
    
    # Calculate lengths to detect potential truncation vs normal padding
    declared_length = udp_layer.len
    actual_length = len(raw_bytes)
    
    # Safely extract L7 Application payload, handling the NoPayload edge case
    if isinstance(udp_layer.payload, NoPayload):
        app_payload = b""
    else:
        app_payload = udp_layer.payload.original
        
    return {
        "status": "OK",
        "transport_protocol": "UDP",
        "src_port": udp_layer.sport,
        "dst_port": udp_layer.dport,
        
        # UDP-specific fields (minimal footprint compared to TCP)
        "transport_fields": {
            "length": declared_length,
            # True ONLY if the actual payload is shorter than declared (malformed/truncated).
            # If actual > declared, it's typically harmless Ethernet padding (e.g., small DNS queries).
            "length_mismatch": actual_length < declared_length,
        },
        
        # Raw bytes ready for the Application layer parser (HTTP, DNS, etc.)
        "app_payload": app_payload
    }

if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST UDP PARSER ===")
    
    # Test 1: Valid UDP packet with padded length (Simulating small DNS over Ethernet)
    print("\n--- Valid Packet (With Padding) ---")
    dummy_udp = UDP(sport=12345, dport=53) / b"DNS Query"
    # Scapy builds it, declared length will be 8 (header) + 9 (payload) = 17
    built_udp = bytes(UDP(bytes(dummy_udp))) 
    # Manually append 20 bytes of 0x00 to simulate Ethernet padding
    padded_bytes = built_udp + (b"\x00" * 20)
    
    print(parse_udp(padded_bytes))

    # Test 2: length_mismatch = true 
    print("\n--- Length Mismatch (Declared > Actual) ---")
    fake_mismatch = built_udp[:10]  # Taking only the first 10 bytes of a valid UDP header to simulate truncation
    print(parse_udp(fake_mismatch))

    # Test 3: Truncated Packet - Under the minimum UDP header length (8 bytes)
    print("\n--- Truncated Packet ---")
    print(parse_udp(built_udp[:6]))