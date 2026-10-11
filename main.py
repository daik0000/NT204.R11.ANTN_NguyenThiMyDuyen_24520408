import argparse
import logging
import sys

from src.capture.pcap_reader import read_pcap
from src.capture.live_capture import capture_live
from src.pipeline.pipeline import Pipeline
from src.logging.jsonl_logger import JSONLLogger
from src.utils.config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="IDS Packet Capture, Preprocessor & Flow Tracker Engine")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", type=str, help="Path to the PCAP file for offline analysis")
    group.add_argument("--interface", type=str, help="Network interface for live capture (e.g., eth0)")

    parser.add_argument(
        "--config",
        type=str,
        default="config/settings.yaml",
        help="Path to the YAML configuration file (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--events-output",
        type=str,
        default=None,
        help="Path to the output JSONL file for logging packet events (default: output/events.jsonl)",
    )
    parser.add_argument(
        "--flows-output",
        type=str,
        default="output/flows.jsonl",
        help="Path to the output JSONL file for logging exported flows (default: output/flows.jsonl)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Backward-compatible alias for --events-output",
    )

    parser.add_argument(
        "--bpf-filter",
        type=str,
        default="tcp or udp",
        help="Kernel-level BPF filter. Only applies to live capture (--interface). Ignored for --pcap.",
    )

    args = parser.parse_args()

    events_output_path = args.events_output or args.output or "output/events.jsonl"
    flows_output_path = args.flows_output or "output/flows.jsonl"

    packet_count = 0
    active_before_flush = 0
    pipeline = None

    try:
        cfg = load_config(args.config)

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

        with JSONLLogger(file_path=events_output_path) as event_logger, \
             JSONLLogger(file_path=flows_output_path) as flow_logger:

            pipeline = Pipeline(cfg=cfg, event_logger=event_logger, flow_logger=flow_logger)

            try:
                for timestamp, raw_bytes in capture_stream:
                    packet_count += 1
                    event = pipeline.process(timestamp, raw_bytes, packet_count)

                    if event.status == "MALFORMED":
                        logger.warning("Packet #%d MALFORMED: %s", event.packet_id, event.error_info)
                    elif event.status == "UNKNOWN":
                        logger.debug("Packet #%d UNKNOWN (Non-IPv4/Ignored)", event.packet_id)
                    elif event.status == "IGNORED":
                        logger.debug("Packet #%d IGNORED (Unknown Application Protocol)", event.packet_id)
                    elif packet_count % 100 == 0:
                        logger.info("Captured and processed %d packets...", packet_count)
            finally:
                active_before_flush = pipeline.flow_tracker.active_flow_count()
                pipeline.flush()

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
        flows_exported = pipeline.flows_exported if pipeline is not None else 0
        counts = pipeline.preprocess_counts if pipeline is not None else {"valid": 0, "partial": 0, "invalid": 0}
        logger.info(
            "System shutdown complete. Summary: packets=%d, flows=%d, active_before_flush=%d, "
            "preprocess_status={valid=%d, partial=%d, invalid=%d}",
            packet_count,
            flows_exported,
            active_before_flush,
            counts.get("valid", 0),
            counts.get("partial", 0),
            counts.get("invalid", 0),
        )


if __name__ == "__main__":
    main()