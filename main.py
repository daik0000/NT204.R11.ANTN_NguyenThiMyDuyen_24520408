import argparse
import logging
import sys
from contextlib import ExitStack
from pathlib import Path

from src.capture.pcap_reader import read_pcap
from src.capture.live_capture import capture_live
from src.pipeline.pipeline import Pipeline
from src.engine.engine import engine_enabled
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
        "--rules",
        action="append",
        default=None,
        metavar="FILE",
        help="Extra Snort-style rules file; may be given several times. Added after engine.rule_files "
             "in config. A path that does not exist or is a directory stops the program with exit code 1.",
    )
    parser.add_argument(
        "--detections-output",
        type=str,
        default="output/detections.jsonl",
        help="Path to the output JSONL file for Detection Events (default: output/detections.jsonl). "
             "Not created when engine.enabled is false.",
    )
    parser.add_argument(
        "--rules-report",
        type=str,
        default="output/rules_report.jsonl",
        help="Path to the JSONL report of every rule line read, with its status and reason "
             "(default: output/rules_report.jsonl). Replaced on each run; not written when engine.enabled is false.",
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
    detections_output_path = args.detections_output or "output/detections.jsonl"
    rules_report_path = args.rules_report or "output/rules_report.jsonl"

    packet_count = 0
    active_before_flush = 0
    pipeline = None

    try:
        cfg = load_config(args.config)

        for rules_path in args.rules or []:
            if Path(rules_path).is_dir():
                raise FileNotFoundError(f"--rules: '{rules_path}' is a directory, not a rules file")
            if not Path(rules_path).is_file():
                raise FileNotFoundError(f"--rules: rules file not found: '{rules_path}'")
        engine_on = engine_enabled(cfg)

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

        with ExitStack() as stack:
            event_logger = stack.enter_context(JSONLLogger(file_path=events_output_path))
            flow_logger = stack.enter_context(JSONLLogger(file_path=flows_output_path))
            # With the engine off nothing is written for Part 3: the outputs are exactly those of Part 2.
            detection_logger = (stack.enter_context(JSONLLogger(file_path=detections_output_path))
                                if engine_on else None)

            pipeline = Pipeline(cfg=cfg, event_logger=event_logger, flow_logger=flow_logger,
                                detection_logger=detection_logger, extra_rule_paths=args.rules,
                                rules_report_path=rules_report_path)

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
        engine = pipeline.engine if pipeline is not None else None
        if engine is not None and engine.enabled:
            logger.info("%s", engine.summary())
            if not engine.stats.is_consistent():
                logger.warning("Engine statistics are inconsistent: %s", engine.stats.summary())
        rep = engine.report if engine is not None else None
        stats = engine.stats if engine is not None else None
        logger.info(
            "System shutdown complete. Summary: packets=%d, flows=%d, active_before_flush=%d, "
            "preprocess_status={valid=%d, partial=%d, invalid=%d}, "
            "rules(loaded=%d, invalid=%d, unsupported=%d), events_evaluated=%d, candidates=%d, detections=%d",
            packet_count,
            flows_exported,
            active_before_flush,
            counts.get("valid", 0),
            counts.get("partial", 0),
            counts.get("invalid", 0),
            rep.valid if rep is not None else 0,
            rep.invalid if rep is not None else 0,
            rep.unsupported if rep is not None else 0,
            stats.events_evaluated if stats is not None else 0,
            stats.candidate_rules if stats is not None else 0,
            pipeline.detections_written if pipeline is not None else 0,
        )


if __name__ == "__main__":
    main()