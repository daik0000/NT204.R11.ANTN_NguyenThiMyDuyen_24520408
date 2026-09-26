import re
import struct
import yaml
import logging
from typing import Dict, Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

FALLBACK_PORTS: Dict[int, str] = {
    80: "HTTP",
    53: "DNS",
    443: "HTTPS",
    25: "SMTP",
    587: "SMTP"
}

def load_known_ports(config_path: str = "config/settings.yaml") -> Dict[int, str]:
    try:
        path = Path(config_path)
        if not path.is_file():
            logger.debug("Config file %s not found. Using fallback port mappings.", config_path)
            return FALLBACK_PORTS
            
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            
        ports_config = config.get("ports", {})
        if not ports_config:
            return FALLBACK_PORTS
            
        return {int(port): str(proto) for port, proto in ports_config.items()}
        
    except Exception as e:
        logger.warning("Failed to load ports from %s: %s. Using fallback.", config_path, e)
        return FALLBACK_PORTS

KNOWN_PORTS: Dict[int, str] = load_known_ports()

# Pre-compile regex for SMTP server responses (e.g., "220 ", "250-", "354 ")
SMTP_REPLY_PATTERN = re.compile(br"^\d{3}[ -]")

# HTTP Methods / Status line signatures
HTTP_SIGNATURES = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ",  b"HEAD ", b"OPTIONS ", b"HTTP/1.", b"HTTP/2"
)

def detect_protocol_by_port(src_port: int, dst_port: int) -> str:
    if dst_port in KNOWN_PORTS:
        return KNOWN_PORTS[dst_port]
    if src_port in KNOWN_PORTS:
        return KNOWN_PORTS[src_port]
    return "UNKNOWN"

def detect_protocol_by_payload(payload: bytes) -> str:
    """
    Identifies the protocol based on payload byte signatures.
    Helps detect traffic running on non-standard ports.
    """
    if not payload:
        return "UNKNOWN"

    # 1. HTTP Heuristic
    if payload.startswith(HTTP_SIGNATURES):
        return "HTTP"

    # 2. SMTP Heuristic
    # Client commands
    if payload.startswith((b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:")):
        return "SMTP"
    # Server replies (3 digits followed by space or hyphen)
    if SMTP_REPLY_PATTERN.match(payload):
        return "SMTP"

    # 3. DNS Heuristic (RFC 1035 Header Analysis)
    if len(payload) >= 12:
        try:
            # Parse 12 bytes header: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
            _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
            
            opcode = (flags >> 11) & 0xF
            z_reserved = (flags >> 4) & 0x7
            
            if opcode in (0, 1, 2) and z_reserved == 0:
                if 0 < qdcount <= 10:
                    return "DNS"
        except struct.error:
            pass

    return "UNKNOWN"

def detect_application_protocol(payload: bytes, src_port: int, dst_port: int) -> Tuple[str, Optional[str]]:
    """
    Combines both methods. Payload-based has higher weight and will override Port-based.
    Returns a Tuple: (Protocol, Detection Method)
    """
    port_proto = detect_protocol_by_port(src_port, dst_port)
    payload_proto = detect_protocol_by_payload(payload)

    if payload_proto != "UNKNOWN":
        if port_proto == payload_proto:
            # Both methods agree — highest confidence signal
            return payload_proto, "port+payload"
            
        if port_proto != "UNKNOWN":
            # True conflict — sign of evasion/anomaly
            logger.warning(
                "Protocol evasion anomaly! Port suggests %s but Payload confirms %s. Overriding with Payload.", 
                port_proto, payload_proto
            )
        return payload_proto, "payload"

    if port_proto != "UNKNOWN":
        return port_proto, "port"

    return "UNKNOWN", None

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")
    print("=== TEST PAYLOAD-BASED DETECTOR ===")
    
    # Test 1: HTTP on port 9999 (Non-standard port) -> payload
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com"
    print(f"HTTP evasion (port 9999): {detect_application_protocol(http_payload, src_port=54321, dst_port=9999)}")
    
    # Test 2: SMTP server reply on port 80 -> payload
    smtp_payload = b"220 mail.example.com ESMTP Postfix"
    print(f"SMTP evasion (port 80): {detect_application_protocol(smtp_payload, src_port=80, dst_port=54321)}")
    
    # Test 3: Valid DNS on correct port 53 -> port+payload
    dns_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"example.com"
    print(f"Normal DNS (port 53): {detect_application_protocol(dns_payload, src_port=54321, dst_port=53)}")