import yaml
import logging
from typing import Dict
from pathlib import Path

logger = logging.getLogger(__name__)

FALLBACK_PORTS: Dict[int, str] = {
    80: "HTTP",
    53: "DNS",
    25: "SMTP",
    587: "SMTP"
}

def load_known_ports(config_path: str = "config/settings.yaml") -> Dict[int, str]:
    """
    Loads port mappings from the YAML configuration file.
    Falls back to a default set of ports if the file is missing or invalid.
    """
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

# Initialize the global mapping at module load time
KNOWN_PORTS: Dict[int, str] = load_known_ports()

def detect_protocol_by_port(src_port: int, dst_port: int) -> str:
    """
    Identifies the Application Layer protocol based on port numbers (Port-based).
    This acts as a fast O(1) baseline before payload-based heuristics are applied.
    """
    if dst_port in KNOWN_PORTS:
        return KNOWN_PORTS[dst_port]
        
    if src_port in KNOWN_PORTS:
        return KNOWN_PORTS[src_port]
        
    return "UNKNOWN"

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST PORT-BASED DETECTOR ===")
    
    # Test 1: HTTP Request (Client:54321 -> Server:80)
    print(f"80 (dst) -> {detect_protocol_by_port(src_port=54321, dst_port=80)}")
    
    # Test 2: DNS Response (Server:53 -> Client)
    print(f"53 (src) -> {detect_protocol_by_port(src_port=53, dst_port=12345)}")
    
    # Test 3: Unknown Custom Port
    print(f"9999 (dst) -> {detect_protocol_by_port(src_port=11111, dst_port=9999)}")