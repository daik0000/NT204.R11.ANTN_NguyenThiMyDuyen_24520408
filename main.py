import argparse
import logging
import sys

from src.capture.pcap_reader import read_pcap
from src.capture.live_capture import capture_live
from src.pipeline.pipeline import process_packet
from src.logging.jsonl_logger import JSONLLogger

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="IDS Packet Capture & Parser Engine")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", type=str, help="Path to the PCAP file for offline analysis")
    group.add_argument("--interface", type=str, help="Network interface for live capture (e.g., eth0)")

    parser.add_argument(
        "--bpf-filter",
        type=str,
        default="tcp or udp",
        help="Kernel-level BPF filter. Only applies to live capture (--interface). Ignored for --pcap."
    )

    args = parser.parse_args()
    packet_count = 0

    try:
        if args.pcap:
            if args.bpf_filter != "tcp or udp":
                logger.warning("The '--bpf-filter' argument does not apply to PCAP files and will be ignored.")
            logger.info("Offline Mode: Reading PCAP file '%s'", args.pcap)
            capture_stream = read_pcap(args.pcap)
        elif args.interface:
            logger.info("Live Mode: Listening on interface '%s' | Filter: '%s'", args.interface, args.bpf_filter)
            capture_stream = capture_live(interface=args.interface, bpf_filter=args.bpf_filter)
        else:
            parser.error("Invalid capture mode selected.")
            return

        with JSONLLogger() as logger_jsonl:
            for timestamp, raw_bytes in capture_stream:
                packet_count += 1

                event = process_packet(timestamp, raw_bytes, packet_count)

                if event.status != "IGNORED":
                    logger_jsonl.log_event(event)

                if event.status == "MALFORMED":
                    logger.warning("Packet #%d MALFORMED: %s", event.packet_id, event.error_info)
                elif event.status == "UNKNOWN":
                    logger.debug("Packet #%d UNKNOWN (Non-IPv4/Ignored)", event.packet_id)
                elif event.status == "IGNORED":
                    logger.debug("Packet #%d IGNORED (Unknown Application Protocol)", event.packet_id)
                elif packet_count % 100 == 0:
                    logger.info("Captured and processed %d packets...", packet_count)

    except PermissionError as pe:
        logger.critical("%s", pe)
        sys.exit(1)
    except FileNotFoundError as fe:
        logger.critical("%s", fe)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user (Ctrl+C).")
    except Exception as e:
        logger.critical("Severe system error encountered: %s", e)
        sys.exit(1)
    finally:
        logger.info("System shutdown complete. Total packets processed: %d", packet_count)

if __name__ == "__main__":
    main()