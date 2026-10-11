import json
import logging
import sys

import pytest

import main as cli
from src.pipeline import pipeline as pl


@pytest.fixture(autouse=True)
def fake_layers(monkeypatch):
    # Replace parsers/decoder/preprocessor with tiny fakes so the test only exercises CLI + pipeline wiring
    monkeypatch.setattr(pl, "parse_ipv4", lambda raw: {
        "status": "OK", "network_protocol": "IPv4", "src_ip": f"10.0.0.{raw[1]}", "dst_ip": f"10.0.0.{raw[2]}",
        "network_fields": {"ip_proto_number": 17}, "transport_payload": raw[1:]})
    monkeypatch.setattr(pl, "parse_udp", lambda p: {
        "status": "OK", "transport_protocol": "UDP", "src_port": p[0], "dst_port": p[1],
        "transport_fields": {}, "app_payload": p[2:]})
    monkeypatch.setattr(pl, "detect_application_protocol", lambda **kw: ("DNS", "port"))
    monkeypatch.setattr(pl, "parse_dns", lambda p: {"status": "OK", "app_protocol": "DNS", "app_fields": {}})
    monkeypatch.setattr(pl, "decode_event", lambda e, c: e)

    def pre(e, c):
        p = e.payload or b""
        e.preprocess_status = {b"P": "partial", b"I": "invalid"}.get(p[:1], "valid")
        e.processing_action = "flagged" if e.preprocess_status == "invalid" else "none"
        return e

    monkeypatch.setattr(pl, "preprocess_event", pre)


def pk(sp=1, dp=2, payload=b"q"):
    return b"X" + bytes([sp, dp]) + payload


def run_cli(monkeypatch, tmp_path, packets, extra=()):
    monkeypatch.setattr(cli, "read_pcap", lambda path: iter(packets) if not callable(packets) else packets())
    extra = list(extra)
    if "--config" not in extra:  # the default config path does not exist under tmp_path
        default_cfg = tmp_path / "default.yaml"
        default_cfg.write_text("flow:\n  udp_idle_timeout_sec: 60\n", encoding="utf-8")
        extra += ["--config", str(default_cfg)]
    monkeypatch.setattr(sys, "argv", ["main.py", "--pcap", "x.pcap", *extra])
    cli.main()


def rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def out_args(tmp_path):
    return ["--events-output", str(tmp_path / "e.jsonl"), "--flows-output", str(tmp_path / "f.jsonl")]


def test_end_of_pcap_flushes_every_flow_to_flows_file(monkeypatch, tmp_path):
    run_cli(monkeypatch, tmp_path, [(1.0, pk(1)), (2.0, pk(2)), (3.0, pk(1))], out_args(tmp_path))
    assert len(rows(tmp_path / "e.jsonl")) == 3
    assert sorted(r["close_reason"] for r in rows(tmp_path / "f.jsonl")) == ["flush", "flush"]


def test_ctrl_c_still_flushes_and_exits_normally(monkeypatch, tmp_path):
    def stream():
        yield 1.0, pk(1)
        yield 2.0, pk(2)
        raise KeyboardInterrupt

    run_cli(monkeypatch, tmp_path, stream, out_args(tmp_path))  # must not raise
    assert len(rows(tmp_path / "f.jsonl")) == 2


def test_missing_pcap_exits_with_code_1(monkeypatch, tmp_path):
    def stream():
        raise FileNotFoundError("no such pcap")
        yield

    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, tmp_path, stream, out_args(tmp_path))
    assert e.value.code == 1


def test_unexpected_error_mid_stream_still_flushes_then_exits_1(monkeypatch, tmp_path):
    def stream():
        yield 1.0, pk(1)
        raise RuntimeError("capture broke")

    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, tmp_path, stream, out_args(tmp_path))
    assert e.value.code == 1 and len(rows(tmp_path / "f.jsonl")) == 1


def test_output_alias_still_sets_the_events_file(monkeypatch, tmp_path):
    run_cli(monkeypatch, tmp_path, [(1.0, pk(1))],
            ["--output", str(tmp_path / "old.jsonl"), "--flows-output", str(tmp_path / "f.jsonl")])
    assert len(rows(tmp_path / "old.jsonl")) == 1


def test_events_output_wins_over_output_alias(monkeypatch, tmp_path):
    run_cli(monkeypatch, tmp_path, [(1.0, pk(1))],
            ["--events-output", str(tmp_path / "new.jsonl"), "--output", str(tmp_path / "old.jsonl"),
             "--flows-output", str(tmp_path / "f.jsonl")])
    assert (tmp_path / "new.jsonl").exists() and not (tmp_path / "old.jsonl").exists()


def test_summary_line_counts_packets_flows_active_and_each_status(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    run_cli(monkeypatch, tmp_path,
            [(1.0, pk(1)), (2.0, pk(2, payload=b"P")), (3.0, pk(3, payload=b"I")), (4.0, pk(4))],
            out_args(tmp_path))
    msg = [r.getMessage() for r in caplog.records if "Summary" in r.getMessage()][-1]
    assert "packets=4" in msg and "flows=3" in msg and "active_before_flush=3" in msg
    assert "valid=2" in msg and "partial=1" in msg and "invalid=1" in msg


def test_summary_is_printed_even_when_the_run_fails(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO)

    def stream():
        yield 1.0, pk(1)
        raise RuntimeError("boom")

    with pytest.raises(SystemExit):
        run_cli(monkeypatch, tmp_path, stream, out_args(tmp_path))
    assert any("Summary" in r.getMessage() and "packets=1" in r.getMessage() for r in caplog.records)


def test_invalid_config_stops_the_program_with_code_1(monkeypatch, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("flow:\n  udp_idle_timeout_sec: -5\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, tmp_path, [(1.0, pk(1))], ["--config", str(bad), *out_args(tmp_path)])
    assert e.value.code == 1


def test_custom_config_timeouts_reach_the_tracker(monkeypatch, tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("flow:\n  udp_idle_timeout_sec: 5\n  sweep_interval_sec: 1\n", encoding="utf-8")
    run_cli(monkeypatch, tmp_path, [(1.0, pk(1)), (50.0, pk(2))], ["--config", str(cfg), *out_args(tmp_path)])
    assert sorted(r["close_reason"] for r in rows(tmp_path / "f.jsonl")) == ["flush", "idle_timeout"]


def test_unknown_policy_from_the_custom_config_is_honoured(monkeypatch, tmp_path):
    monkeypatch.setattr(pl, "detect_application_protocol", lambda **kw: ("UNKNOWN", "none"))
    cfg = tmp_path / "u.yaml"
    cfg.write_text("unknown_policy: skip\n", encoding="utf-8")
    run_cli(monkeypatch, tmp_path, [(1.0, pk(1))], ["--config", str(cfg), *out_args(tmp_path)])
    assert rows(tmp_path / "e.jsonl") == [] and len(rows(tmp_path / "f.jsonl")) == 1