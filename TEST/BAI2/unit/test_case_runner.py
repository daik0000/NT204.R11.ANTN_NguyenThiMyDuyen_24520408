import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
import case_runner as cr
from src.models.event import IDSEvent

# Tiny stand-in for main.py: records the arguments it received and appends to the output files
FAKE_MAIN = textwrap.dedent('''
    import argparse, json, sys
    p = argparse.ArgumentParser()
    p.add_argument("--pcap"); p.add_argument("--events-output"); p.add_argument("--flows-output"); p.add_argument("--config")
    a = p.parse_args()
    if a.pcap.endswith("bad.pcap"):
        sys.stderr.write("boom"); sys.exit(1)
    open(a.events_output, "a").write(json.dumps({"cfg": a.config, "pcap": a.pcap}) + "\\n")
    open(a.flows_output, "a").write(json.dumps({"n": 1}) + "\\n")
''')


@pytest.fixture
def fake_case(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.py").write_text(FAKE_MAIN)
    monkeypatch.setattr(cr, "ROOT", root)
    case = tmp_path / "case"
    case.mkdir()
    return case


def test_run_case_returns_events_and_flows(fake_case):
    ev, fl = cr.run_case(fake_case)
    assert ev[0]["pcap"].endswith("input.pcap") and ev[0]["cfg"] is None and fl == [{"n": 1}]


def test_run_case_forwards_config(fake_case):
    cfg = fake_case / "settings.yaml"
    cfg.write_text("x: 1")
    ev, _ = cr.run_case(fake_case, config_path=cfg)
    assert ev[0]["cfg"] == str(cfg.resolve())


def test_run_case_does_not_accumulate_across_runs(fake_case):
    cr.run_case(fake_case)
    ev, fl = cr.run_case(fake_case)
    assert len(ev) == 1 and len(fl) == 1


def test_run_case_raises_with_stderr_on_failure(fake_case):
    with pytest.raises(RuntimeError, match="boom"):
        cr.run_case(fake_case, pcap_name="bad.pcap")


def test_read_jsonl_missing_file_is_empty(tmp_path):
    assert cr.read_jsonl(tmp_path / "nope.jsonl") == []


def test_run_events_runs_stages_and_flushes():
    e = IDSEvent(packet_id=1, timestamp=1.0, raw_length=60, payload_length=8, status="OK",
                 src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=53,
                 network_protocol="IPv4", transport_protocol="UDP", app_protocol="DNS")
    evs, flows = cr.run_events([e])          # default config = config/settings.yaml
    assert evs[0]["flow_id"] and evs[0]["preprocess_status"] in ("valid", "partial")
    assert len(flows) == 1 and flows[0]["close_reason"] == "flush"