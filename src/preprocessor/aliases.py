# Protocol aliases to their standard representation.
# Shared across Preprocessor modules (Validator and Normalizer).
PROTO_ALIASES = {
    "tcp": "TCP", 
    "udp": "UDP", 
    "icmp": "ICMP",
    "ip": "IPv4", 
    "ipv4": "IPv4", 
    "ipv6": "IPv6",
    "http": "HTTP", 
    "smtp": "SMTP", 
    "dns": "DNS",
    "unknown": "UNKNOWN"  # Added to prevent normalizing unknown into something else
}