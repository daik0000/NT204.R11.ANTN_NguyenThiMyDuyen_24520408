"""Helpers to run the IDS pipeline on one test case and read the results back."""
import copy
import functools
import json
import subprocess
import sys
import tempfile
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

    with tempfile.TemporaryDirectory() as scratch:
        # The rule engine (Part 3) is on by default; its outputs are not evidence of Part 1/2, so they
        # go to a scratch directory instead of the case directory or the repository's output/.
        cmd = [sys.executable, "main.py", "--pcap", str(case_dir / pcap_name),
               "--events-output", str(events_path), "--flows-output", str(flows_path),
               "--detections-output", str(Path(scratch) / "detections.jsonl"),
               "--rules-report", str(Path(scratch) / "rules_report.jsonl")]
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


# --- Part 3 (rule engine) ---

def _cli_path(path) -> str:
    """
    How a path is given to main.py: relative to the repository root (where main.py runs) when the file
    is inside it, so the rules_report.jsonl evidence holds no machine-specific absolute path; otherwise
    as it is.
    """
    path = Path(path)
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _resolve_rules(case_dir: Path, rules) -> List[Path]:
    """
    The rules files of a case. None -> every *.rules file in the case directory, sorted by name;
    [] -> none; a path or a list of paths -> those (a relative path is looked up in the case directory).
    """
    if rules is None:
        return sorted(case_dir.glob("*.rules"))
    if isinstance(rules, (str, Path)):
        rules = [rules]
    out = []
    for r in rules:
        r = Path(r)
        out.append(r if r.is_absolute() or not (case_dir / r).exists() else case_dir / r)
    return out


def _config_without_default_rules(config_path, scratch: Path) -> Path:
    """
    A copy of the config (config_path, or config/settings.yaml) with engine.rule_files emptied, so
    that only the rules of the case are loaded and the sample config/rules/local.rules is not.
    """
    import yaml

    base = Path(config_path).resolve() if config_path is not None else ROOT / "config" / "settings.yaml"
    data = yaml.safe_load(base.read_text(encoding="utf-8")) if base.is_file() else {}
    data = data if isinstance(data, dict) else {}
    engine = data.get("engine") if isinstance(data.get("engine"), dict) else {}
    engine["rule_files"] = []
    data["engine"] = engine
    out = scratch / "settings.yaml"
    out.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return out


def run_case_ids(case_dir, rules=None, config_path=None, pcap_name: str = "input.pcap",
                 timeout: float = 120.0, check: bool = True) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
    """
    Run `python main.py --pcap <case_dir>/<pcap_name> --rules ...` as a subprocess and return
    (events, flows, detections, rules_report). The four JSONL files are written next to the pcap
    (events.jsonl, flows.jsonl, detections.jsonl, rules_report.jsonl) so they stay as evidence, and old
    ones are deleted first, so a leftover can never be mistaken for the result of this run.

    rules: see _resolve_rules (default: every *.rules file of the case directory); files inside the
    repository are passed relative to its root (see _cli_path). The sample rules
    of the config (config/rules/local.rules) are never loaded here: engine.rule_files is emptied in a
    scratch copy of the config, so the case's detections come from the case's rules only.
    config_path: a config to start from (its other settings, e.g. engine.disabled_sids, are kept).
    check: raise RuntimeError (with stderr) if main.py exits non-zero; with False the files that
    exist are still read.
    """
    case_dir = Path(case_dir).resolve()
    paths = {name: case_dir / f"{name}.jsonl" for name in ("events", "flows", "detections", "rules_report")}
    for p in paths.values():
        p.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory() as scratch:
        config = _config_without_default_rules(config_path, Path(scratch))
        cmd = [sys.executable, "main.py", "--pcap", str(case_dir / pcap_name), "--config", str(config),
               "--events-output", str(paths["events"]), "--flows-output", str(paths["flows"]),
               "--detections-output", str(paths["detections"]), "--rules-report", str(paths["rules_report"])]
        for rules_file in _resolve_rules(case_dir, rules):
            cmd += ["--rules", _cli_path(rules_file)]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"main.py exited with {proc.returncode}\n--- stderr ---\n{proc.stderr}")
    return tuple(read_jsonl(paths[name]) for name in ("events", "flows", "detections", "rules_report"))


def run_rules_only(rules_path, cfg: Optional[Dict[str, Any]] = None):
    """
    Load and classify a rules file without any pcap (for the cases about the rule syntax). Returns
    (LoadReport, records, rules): the counters, one RuleRecord per rule line (valid, invalid,
    unsupported or disabled) and the list of active Rule objects, in file order.

    rules_path: a path or a list of paths. cfg: the config to use (default: config/settings.yaml); it is
    not modified, only its engine.rule_files is replaced by rules_path, so engine.disabled_sids and
    engine.default_priority still apply. A file that cannot be read is counted in report.files_failed.
    """
    from src.rules.loader import load_rules
    from src.rules.validator import parse_rule
    from src.utils.config import load_config

    cfg = copy.deepcopy(cfg) if cfg is not None else load_config(str(ROOT / "config" / "settings.yaml"))
    paths = [rules_path] if isinstance(rules_path, (str, Path)) else list(rules_path)
    cfg["engine"]["rule_files"] = [{"path": str(Path(p)), "enabled": True} for p in paths]
    rules, report, records = load_rules(cfg, functools.partial(parse_rule, cfg=cfg))
    return report, records, rules
