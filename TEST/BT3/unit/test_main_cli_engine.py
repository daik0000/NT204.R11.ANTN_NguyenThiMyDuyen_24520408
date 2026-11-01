import json
import logging
import sys

import pytest

import main as cli
from pcap_builder import tcp_packet, write_pcap
from src.capture.pcap_reader import read_pcap

GET = b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"
HEAD = "alert tcp any any -> any 80"


def rule(sid, options=""):
    return f'{HEAD} (msg:"r{sid}"; {options} sid:{sid};)'


def frames():
    return [
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "S", ts=1.0),
        tcp_packet("10.0.0.2", 80, "10.0.0.1", 40000, "SA", ts=1.1),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "A", ts=1.2),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "PA", ts=1.3, payload=GET),
    ]


@pytest.fixture
def env(tmp_path):
    """A pcap, a config pointing at one rules file, and a place for the outputs."""
    pcap = write_pcap(frames(), str(tmp_path / "in.pcap"))
    rules_a = tmp_path / "a.rules"
    rules_a.write_text("\n".join([rule(1, 'content:"../";'), "this is not a rule",
                                  'alert icmp any any -> any any (msg:"i"; sid:9;)', rule(2, "flags:S;")]) + "\n",
                       encoding="utf-8")
    cfg = tmp_path / "settings.yaml"
    cfg.write_text(f"engine:\n  rule_files:\n    - path: {rules_a}\n      enabled: true\n", encoding="utf-8")
    out = tmp_path / "case"
    return dict(tmp=tmp_path, pcap=pcap, rules_a=rules_a, cfg=cfg, out=out)


def args(env, *extra, with_outputs=True):
    base = ["--pcap", env["pcap"], "--config", str(env["cfg"])]
    if with_outputs:
        out = env["out"]
        base += ["--events-output", str(out / "events.jsonl"), "--flows-output", str(out / "flows.jsonl"),
                 "--detections-output", str(out / "detections.jsonl"), "--rules-report", str(out / "rules_report.jsonl")]
    return base + list(extra)


def run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["main.py", *argv])
    cli.main()


def rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def summary_of(caplog):
    return [r.getMessage() for r in caplog.records if "Summary" in r.getMessage()][-1]


# --- outputs -----------------------------------------------------------------------------------------------------------------

def test_detections_and_rules_report_go_to_the_given_case_directory(monkeypatch, env):
    run(monkeypatch, args(env))
    out = env["out"]
    detections = rows(out / "detections.jsonl")
    assert [(d["sid"], d["packet_id"]) for d in detections] == [(2, 1), (1, 4)]
    assert detections[1]["matched"] == [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]
    assert [(r["line"], r["status"]) for r in rows(out / "rules_report.jsonl")] == [
        (1, "valid"), (2, "invalid"), (3, "unsupported"), (4, "valid")]
    assert len(rows(out / "events.jsonl")) == 4 and rows(out / "flows.jsonl")


def test_default_output_paths(monkeypatch, env):
    monkeypatch.chdir(env["tmp"])
    run(monkeypatch, args(env, with_outputs=False))
    assert [d["sid"] for d in rows(env["tmp"] / "output" / "detections.jsonl")] == [2, 1]
    assert len(rows(env["tmp"] / "output" / "rules_report.jsonl")) == 4
    assert (env["tmp"] / "output" / "events.jsonl").exists() and (env["tmp"] / "output" / "flows.jsonl").exists()


def test_help_shows_the_new_options(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--help"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    text = capsys.readouterr().out
    assert e.value.code == 0
    for option in ("--rules", "--detections-output", "--rules-report", "output/detections.jsonl",
                   "output/rules_report.jsonl"):
        assert option in text


def test_rules_report_is_replaced_but_detections_are_appended_like_events(monkeypatch, env):
    run(monkeypatch, args(env))
    run(monkeypatch, args(env))
    out = env["out"]
    assert len(rows(out / "rules_report.jsonl")) == 4              # replaced
    assert len(rows(out / "detections.jsonl")) == 4                # appended, as events.jsonl is
    assert len(rows(out / "events.jsonl")) == 8


# --- --rules -------------------------------------------------------------------------------------------------------------------

def test_rules_can_be_repeated_and_are_added_after_the_configured_files(monkeypatch, env):
    b = env["tmp"] / "b.rules"
    b.write_text(rule(30, 'content:"GET";') + "\n", encoding="utf-8")
    c = env["tmp"] / "c.rules"
    c.write_text(rule(40, "flags:PA;") + "\n", encoding="utf-8")
    run(monkeypatch, args(env, "--rules", str(b), "--rules", str(c)))
    report = rows(env["out"] / "rules_report.jsonl")
    assert [r["file"] for r in report] == [str(env["rules_a"])] * 4 + [str(b), str(c)]
    detections = rows(env["out"] / "detections.jsonl")
    assert [d["sid"] for d in detections if d["packet_id"] == 4] == [1, 30, 40]    # config file first, then b, then c


def test_a_missing_rules_file_exits_1_with_a_clear_message(monkeypatch, env, caplog):
    missing = env["tmp"] / "nope.rules"
    with pytest.raises(SystemExit) as e, caplog.at_level(logging.INFO):
        run(monkeypatch, args(env, "--rules", str(missing)))
    assert e.value.code == 1
    messages = " ".join(r.getMessage() for r in caplog.records if r.levelno >= logging.CRITICAL)
    assert "--rules" in messages and "not found" in messages and str(missing) in messages
    assert not env["out"].exists()                                  # nothing was created before the check


def test_a_directory_as_rules_file_exits_1_with_a_clear_message(monkeypatch, env, caplog):
    with pytest.raises(SystemExit) as e, caplog.at_level(logging.INFO):
        run(monkeypatch, args(env, "--rules", str(env["tmp"])))
    assert e.value.code == 1
    assert any("directory" in r.getMessage() for r in caplog.records if r.levelno >= logging.CRITICAL)


def test_one_bad_path_among_good_ones_still_exits_1(monkeypatch, env):
    good = env["tmp"] / "g.rules"
    good.write_text(rule(5) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        run(monkeypatch, args(env, "--rules", str(good), "--rules", str(env["tmp"] / "nope.rules")))
    assert e.value.code == 1


def test_a_rules_file_full_of_errors_is_not_fatal(monkeypatch, env, caplog):
    bad = env["tmp"] / "bad.rules"
    bad.write_text("garbage\n" + 'alert tcp any any -> any 80 (msg:"x"; pcre:"/a/"; sid:77;)\n', encoding="utf-8")
    caplog.set_level(logging.INFO)
    run(monkeypatch, args(env, "--rules", str(bad)))
    assert "rules(loaded=2, invalid=2, unsupported=2)" in summary_of(caplog)


# --- the engine switched off ---------------------------------------------------------------------------------------------------

def outputs_args(out):
    return ["--events-output", str(out / "events.jsonl"), "--flows-output", str(out / "flows.jsonl"),
            "--detections-output", str(out / "detections.jsonl"), "--rules-report", str(out / "rules_report.jsonl")]


def test_engine_disabled_gives_exactly_the_part_2_outputs(monkeypatch, env):
    on_out, off_out = env["tmp"] / "on", env["tmp"] / "off"
    run(monkeypatch, ["--pcap", env["pcap"], "--config", str(env["cfg"]), *outputs_args(on_out)])
    off_cfg = env["tmp"] / "off.yaml"
    off_cfg.write_text(env["cfg"].read_text(encoding="utf-8") + "  enabled: false\n", encoding="utf-8")
    run(monkeypatch, ["--pcap", env["pcap"], "--config", str(off_cfg), *outputs_args(off_out)])
    assert (off_out / "events.jsonl").read_bytes() == (on_out / "events.jsonl").read_bytes()      # byte for byte
    assert (off_out / "flows.jsonl").read_bytes() == (on_out / "flows.jsonl").read_bytes()
    assert (on_out / "detections.jsonl").exists() and (on_out / "rules_report.jsonl").exists()
    assert not (off_out / "detections.jsonl").exists() and not (off_out / "rules_report.jsonl").exists()


def test_engine_disabled_ignores_rules_with_a_warning_but_still_checks_the_path(monkeypatch, env, caplog):
    off_cfg = env["tmp"] / "off.yaml"
    off_cfg.write_text("engine:\n  enabled: false\n", encoding="utf-8")
    x = env["tmp"] / "x.rules"
    x.write_text(rule(1) + "\n", encoding="utf-8")
    argv = ["--pcap", env["pcap"], "--config", str(off_cfg), "--events-output", str(env["out"] / "e.jsonl"),
            "--flows-output", str(env["out"] / "f.jsonl")]
    with caplog.at_level(logging.WARNING):
        run(monkeypatch, argv + ["--rules", str(x)])
    assert any("--rules ignored" in r.getMessage() for r in caplog.records)
    with pytest.raises(SystemExit) as e:
        run(monkeypatch, argv + ["--rules", str(env["tmp"] / "nope.rules")])
    assert e.value.code == 1


# --- --interface uses the same path ---------------------------------------------------------------------------------------------

def test_live_mode_writes_the_same_outputs(monkeypatch, env):
    packets = list(read_pcap(env["pcap"]))
    seen = {}

    def fake_capture_live(interface, bpf_filter):
        seen["args"] = (interface, bpf_filter)
        return iter(packets)

    monkeypatch.setattr(cli, "capture_live", fake_capture_live)
    argv = ["--interface", "eth0", "--config", str(env["cfg"]), *args(env)[4:]]
    run(monkeypatch, argv)
    assert seen["args"] == ("eth0", "tcp or udp")
    assert [d["sid"] for d in rows(env["out"] / "detections.jsonl")] == [2, 1]
    assert len(rows(env["out"] / "rules_report.jsonl")) == 4


def test_ctrl_c_keeps_the_detections_already_written(monkeypatch, env):
    packets = list(read_pcap(env["pcap"]))

    def stream():
        yield from packets
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "read_pcap", lambda path: stream())
    run(monkeypatch, args(env))                                      # must not raise
    assert [d["sid"] for d in rows(env["out"] / "detections.jsonl")] == [2, 1]


# --- summary line ----------------------------------------------------------------------------------------------------------------

def test_summary_keeps_the_part_2_fields_and_adds_the_engine_fields(monkeypatch, env, caplog):
    caplog.set_level(logging.INFO)
    run(monkeypatch, args(env))
    msg = summary_of(caplog)
    assert msg.startswith("System shutdown complete. Summary: packets=4, flows=1, active_before_flush=1, "
                          "preprocess_status={valid=4, partial=0, invalid=0}")
    assert msg.endswith(", rules(loaded=2, invalid=1, unsupported=1), events_evaluated=4, candidates=6, detections=2")


def test_summary_counts_extra_rules_and_more_detections(monkeypatch, env, caplog):
    caplog.set_level(logging.INFO)
    b = env["tmp"] / "b.rules"
    b.write_text(rule(30, 'content:"GET";') + "\n", encoding="utf-8")
    run(monkeypatch, args(env, "--rules", str(b)))
    msg = summary_of(caplog)
    assert "rules(loaded=3, invalid=1, unsupported=1)" in msg and "detections=3" in msg
    assert "candidates=9" in msg                                    # 3 rules for each of the 3 packets sent to port 80


def test_summary_has_zeros_for_the_engine_when_it_is_off(monkeypatch, env, caplog):
    caplog.set_level(logging.INFO)
    off_cfg = env["tmp"] / "off.yaml"
    off_cfg.write_text("engine:\n  enabled: false\n", encoding="utf-8")
    run(monkeypatch, ["--pcap", env["pcap"], "--config", str(off_cfg), "--events-output", str(env["out"] / "e.jsonl"),
                      "--flows-output", str(env["out"] / "f.jsonl")])
    msg = summary_of(caplog)
    assert msg.startswith("System shutdown complete. Summary: packets=4, flows=1")
    assert msg.endswith("rules(loaded=0, invalid=0, unsupported=0), events_evaluated=0, candidates=0, detections=0")


def test_the_engine_statistics_line_is_logged_at_the_end(monkeypatch, env, caplog):
    caplog.set_level(logging.INFO)
    run(monkeypatch, args(env))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("rules: loaded=")]
    assert lines and "| engine: events_evaluated=4" in lines[-1] and "matches=2" in lines[-1]


# --- paths given twice, report in a new directory -----------------------------------------------------------------------------

def test_the_same_rules_file_given_twice_or_also_in_the_config_is_loaded_once(monkeypatch, env, caplog):
    caplog.set_level(logging.INFO)
    run(monkeypatch, args(env, "--rules", str(env["rules_a"]), "--rules", str(env["rules_a"])))
    report = rows(env["out"] / "rules_report.jsonl")
    assert len(report) == 4 and {r["status"] for r in report} == {"valid", "invalid", "unsupported"}
    assert "rules(loaded=2, invalid=1, unsupported=1)" in summary_of(caplog)
    assert [d["sid"] for d in rows(env["out"] / "detections.jsonl")] == [2, 1]


def test_a_copy_of_a_rules_file_shows_up_as_duplicate_sids(monkeypatch, env, caplog):
    copy = env["tmp"] / "copy.rules"
    copy.write_text(env["rules_a"].read_text(encoding="utf-8"), encoding="utf-8")
    caplog.set_level(logging.INFO)
    run(monkeypatch, args(env, "--rules", str(copy)))
    report = rows(env["out"] / "rules_report.jsonl")
    dups = [r for r in report if r["reason"] == "invalid:duplicate_sid"]
    assert [r["sid"] for r in dups] == [1, 2] and all(r["file"] == str(copy) for r in dups)
    assert "rules(loaded=2, invalid=4, unsupported=2)" in summary_of(caplog)    # 2 copies of sids + 2 garbage lines
    assert [d["sid"] for d in rows(env["out"] / "detections.jsonl")] == [2, 1]      # the copies never fire


def test_rules_report_in_a_directory_that_does_not_exist_yet(monkeypatch, env):
    target = env["tmp"] / "new" / "nested" / "rules_report.jsonl"
    run(monkeypatch, args(env, "--rules-report", str(target)))
    assert len(rows(target)) == 4


def test_detections_output_in_a_directory_that_does_not_exist_yet(monkeypatch, env):
    target = env["tmp"] / "deep" / "er" / "detections.jsonl"
    run(monkeypatch, args(env, "--detections-output", str(target)))
    assert [d["sid"] for d in rows(target)] == [2, 1]
