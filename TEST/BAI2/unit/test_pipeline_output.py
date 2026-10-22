import json

import pytest

from src.logging.jsonl_logger import JSONLLogger
from src.pipeline import pipeline as pl
from src.pipeline.pipeline import Pipeline


@pytest.fixture(autouse=True)
def fake_layers(monkeypatch):
    # raw = b"X" + sport + dport + payload
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
        e.preprocess_status, e.processing_action = "valid", "none"
        return e

    monkeypatch.setattr(pl, "preprocess_event", pre)


def pk(sp=1, dp=2):
    return b"X" + bytes([sp, dp]) + b"q"


def lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.fixture
def paths(tmp_path):
    return str(tmp_path / "events.jsonl"), str(tmp_path / "flows.jsonl")


def make(paths, cfg=None):
    return Pipeline(cfg or {}, event_logger=JSONLLogger(paths[0]), flow_logger=JSONLLogger(paths[1]))


def test_flows_file_stays_empty_while_flows_are_active(paths):
    p = make(paths)
    p.process(1.0, pk(1), 1)
    p.process(2.0, pk(2), 2)
    assert lines(paths[1]) == [] and len(lines(paths[0])) == 2
    p.close()


def test_flush_writes_exactly_one_line_per_flow(paths):
    p = make(paths)
    p.process(1.0, pk(1, 2), 1)
    p.process(1.1, pk(2, 1), 2)        # reverse direction, same flow
    p.process(2.0, pk(3, 4), 3)
    assert p.flush() == 2
    rows = lines(paths[1])
    assert len(rows) == 2 and len({r["flow_id"] for r in rows}) == 2
    p.close()


def test_flow_line_has_the_flow_schema_with_duration_after_last_seen(paths):
    p = make(paths)
    p.process(1.0, pk(1, 2), 1)
    p.process(3.5, pk(2, 1), 2)
    p.flush()
    p.close()
    row = lines(paths[1])[0]
    keys = list(row)
    assert keys.index("duration") == keys.index("last_seen") + 1 and row["duration"] == 2.5
    assert row["protocol"] == "UDP" and row["state"] == "ACTIVE" and row["close_reason"] == "flush"
    assert (row["fwd_packet_count"], row["bwd_packet_count"], row["packet_count"]) == (1, 1, 2)
    assert row["application_protocol"] == "DNS"


def test_expired_flow_is_written_when_it_expires_not_at_the_end(paths):
    p = make(paths, {"flow": {"udp_idle_timeout_sec": 5, "sweep_interval_sec": 1}})
    p.process(1.0, pk(1), 1)
    p.process(50.0, pk(2), 2)
    assert [r["close_reason"] for r in lines(paths[1])] == ["idle_timeout"]
    p.close()
    assert [r["close_reason"] for r in lines(paths[1])] == ["idle_timeout", "flush"]


def test_a_flow_is_never_written_twice(paths):
    p = make(paths, {"flow": {"udp_idle_timeout_sec": 5, "sweep_interval_sec": 1}})
    p.process(1.0, pk(1), 1)
    p.process(50.0, pk(2), 2)
    p.flush()
    p.flush()
    p.close()
    p.close()
    ids = [r["flow_id"] for r in lines(paths[1])]
    assert len(ids) == len(set(ids)) == 2


def test_events_and_flows_go_to_different_files(paths):
    p = make(paths)
    p.process(1.0, pk(), 1)
    p.close()
    ev, fl = lines(paths[0]), lines(paths[1])
    assert "packet_id" in ev[0] and "flow_id" in ev[0] and "payload" not in ev[0]
    assert "packet_count" in fl[0] and "packet_id" not in fl[0]
    assert ev[0]["flow_id"] == fl[0]["flow_id"]


def test_eviction_writes_the_evicted_flow_immediately(paths):
    p = make(paths, {"flow": {"max_active_flows": 1}})
    p.process(1.0, pk(1), 1)
    p.process(2.0, pk(2), 2)
    assert [r["close_reason"] for r in lines(paths[1])] == ["evicted"]
    p.close()


def test_close_flushes_before_closing_the_files(paths):
    p = make(paths)
    p.process(1.0, pk(), 1)
    p.close()
    assert len(lines(paths[1])) == 1
    assert p.event_logger._file.closed and p.flow_logger._file.closed


def test_context_manager_flushes_on_exit(paths):
    with make(paths) as p:
        p.process(1.0, pk(), 1)
    assert len(lines(paths[1])) == 1


def test_context_manager_flushes_even_when_the_body_raises(paths):
    with pytest.raises(RuntimeError):
        with make(paths) as p:
            p.process(1.0, pk(), 1)
            raise RuntimeError("Ctrl+C stand-in")
    assert len(lines(paths[1])) == 1


def test_unwritable_flow_record_does_not_stop_the_pipeline(paths):
    p = make(paths)
    p.process(1.0, pk(1), 1)
    p.flow_logger.close()                     # simulate a write failure on the flows file
    p.process(2.0, pk(2), 2)
    assert p.flush() == 2
    assert p.flow_logger.write_errors == 2
    p.close()


def test_ignored_events_never_reach_events_file_but_their_flow_does(paths, monkeypatch):
    monkeypatch.setattr(pl, "detect_application_protocol", lambda **kw: ("UNKNOWN", "none"))
    p = make(paths, {"unknown_policy": "skip"})
    p.process(1.0, pk(), 1)
    p.close()
    assert lines(paths[0]) == [] and len(lines(paths[1])) == 1