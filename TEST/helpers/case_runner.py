"""Helpers to run the IDS pipeline on one test case and read the results back."""
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]  # repository root (contains main.py)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def read_jsonl(path) -> List[Dict[str, Any]]:
    """Read a JSON Lines file; a missing file means 'nothing was written'."""
    path = Path(path)
    if not path.is_file():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_case(case_dir, config_path=None, pcap_name: str = "input.pcap",
             timeout: float = 120.0) -> Tuple[List[Dict], List[Dict]]:
    """
    Run `python main.py --pcap <case_dir>/<pcap_name>` as a subprocess and return (events, flows).
    Output files are written next to the pcap (events.jsonl / flows.jsonl) so they stay as evidence.
    """
    case_dir = Path(case_dir).resolve()
    events_path = case_dir / "events.jsonl"
    flows_path = case_dir / "flows.jsonl"
    for p in (events_path, flows_path):  # never read leftovers from an earlier run
        p.unlink(missing_ok=True)

    cmd = [sys.executable, "main.py", "--pcap", str(case_dir / pcap_name),
           "--events-output", str(events_path), "--flows-output", str(flows_path)]
    if config_path is not None:
        cmd += ["--config", str(Path(config_path).resolve())]

    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"main.py exited with {proc.returncode}\n--- stderr ---\n{proc.stderr}")
    return read_jsonl(events_path), read_jsonl(flows_path)


def run_events(events, cfg: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict], List[Dict]]:
    """
    Feed ready-made IDSEvent objects through Decoder -> Preprocessor -> Flow Tracker in-process
    (same order and policy routing as Pipeline.process, minus the Parser). Returns (events, flows) as dicts.
    Events skipped/dropped by policy are returned too (so a test can assert on them) but never reach the tracker.
    """
    from src.decoder.decoder import decode_event
    from src.preprocessor.preprocessor import preprocess_event
    from src.flow.tracker import FlowTracker
    from src.utils.config import load_config

    if cfg is None:
        cfg = load_config(str(ROOT / "config" / "settings.yaml"))

    flows: List[Dict] = []
    tracker = FlowTracker(cfg, on_export=lambda flow: flows.append(flow.to_dict()))
    out: List[Dict] = []
    for event in events:
        if getattr(event, "status", None) != "MALFORMED":
            event = decode_event(event, cfg)
        event = preprocess_event(event, cfg)
        if getattr(event, "processing_action", None) not in ("skipped", "dropped"):
            event = tracker.update(event)
        out.append(event.to_dict())
    tracker.flush()
    return out, flows