import os
import logging
from typing import Iterator, Tuple
from scapy.utils import PcapReader

logger = logging.getLogger(__name__)

def read_pcap(file_path: str) -> Iterator[Tuple[float, bytes]]:
    """
    Reads a PCAP file packet by packet and yields a generator of tuples containing the timestamp and raw bytes of each packet.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PCAP file not found: '{file_path}'")

    try:
        with PcapReader(file_path) as pcap:
            for pkt in pcap:
                try:
                    timestamp = float(pkt.time)
                    
                    # CRITICAL: Use pkt.original instead of bytes(pkt).
                    # bytes(pkt) triggers Scapy's internal build() which might alter 
                    # malformed packets (e.g., recalculating checksums, modifying padding).
                    # pkt.original preserves the exact raw bytes read from the file.
                    raw_bytes = pkt.original
                    
                    yield (timestamp, raw_bytes)
                except Exception as pkt_err:
                    logger.warning("Skipping a corrupted packet in PCAP: %s", pkt_err)
                    continue
                    
    except EOFError:
        # File-level error: Catch truncated PCAPs at the iterator level
        logger.warning("Reached EOF but PCAP file '%s' appears to be truncated.", file_path)
    except Exception as e:
        # Severe structural errors preventing further reading
        logger.error("Structural error while reading PCAP file '%s': %s", file_path, e)

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    if len(sys.argv) < 2:
        print("Uses: python src/capture/pcap_reader.py <path/to/file.pcap>")
        sys.exit(1)

    test_file = sys.argv[1]
    logger.info(f"Reading file: {test_file}")
    
    packet_count = 0
    try:
        for timestamp, raw_bytes in read_pcap(test_file):
            packet_count += 1
            
            # Print the first 5 packets for verification
            if packet_count <= 5:
                print(f"Packet #{packet_count} | Timestamp: {timestamp} | Length: {len(raw_bytes)} bytes")
                logger.debug(f"Packet #{packet_count} content: {raw_bytes}")
        logger.info(f"Completed! Successfully read a total of {packet_count} packets.")
    except Exception as e:
        logger.error(f"Test failed: {e}")