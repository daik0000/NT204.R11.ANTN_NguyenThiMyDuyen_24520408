import dataclasses
from types import SimpleNamespace as NS

import pytest

from src.flow.tracker import FlowTracker
from src.models.flow import Flow
from src.pipeline import pipeline as pl
from src.pipeline.pipeline import Pipeline, process_packet


@pytest.fixture(autouse=True)
def fake_layers(monkeypatch):
    """Replace every parser with a tiny deterministic stub, so the test checks only pipeline wiring."""
    def ipv4(raw):
        if raw.startswith(b"U"):
            return {"status": "UNKNOWN"}
        if raw.startswith(b"M"):
            return {"status": "MALFORMED", "error_info": {"layer": "network"}}
        proto = 17 if raw[1:2] == b"u" else 6
        return {"status": "OK", "network_protocol": "IPv4", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "network_fields": {"ip_proto_number": proto}, "transport_payload": raw[2:]}

    def tcp(p):
        if p.startswith(b"!"):
            return {"status": "MALFORMED", "error_info": {"layer": "transport"}}
        return {"status": "OK", "transport_protocol": "TCP", "src_port": 1000, "dst_port": 80,
                "transport_fields": {"flags": ["SYN"]}, "app_payload": p[1:]}

    def udp(p):
        return {"status": "OK", "transport_protocol": "UDP", "src_port": 1000, "dst_port": 53,
                "transport_fields": {}, "app_payload": p}

    def detect(payload, src_port, dst_port, packet_id=None):
        if payload.startswith(b"GET"):
            return "HTTP", "payload"
        if payload.startswith(b"D"):
            return "DNS", "port"
        return "UNKNOWN", "none"

    monkeypatch.setattr(pl, "parse_ipv4", ipv4)
    monkeypatch.setattr(pl, "parse_tcp", tcp)
    monkeypatch.setattr(pl, "parse_udp", udp)
    monkeypatch.setattr(pl, "detect_application_protocol", detect)
    monkeypatch.setattr(pl, "parse_http", lambda p: {"status": "OK", "app_protocol": "HTTP", "app_fields": {"method": "GET"}})
    monkeypatch.setattr(pl, "parse_dns", lambda p: {"status": "MALFORMED", "error_info": {"layer": "application"}})
    monkeypatch.setattr(pl, "parse_smtp", lambda p: None)

    def neutral_preprocessor(event, cfg):
        event.preprocess_status, event.processing_action = "valid", "none"
        return event

    monkeypatch.setattr(pl, "decode_event", lambda event, cfg: event)
    monkeypatch.setattr(pl, "preprocess_event", neutral_preprocessor)


RAW = [b"Xt", b"Xt!", b"XtGET /a", b"XtZZZ", b"Xu", b"XuDns", b"U", b"M"]


@pytest.mark.parametrize("policy", ["log", "skip"])
@pytest.mark.parametrize("raw", RAW)
def test_pipeline_process_matches_process_packet(monkeypatch, raw, policy):
    monkeypatch.setattr(pl, "UNKNOWN_POLICY", policy)
    a = dataclasses.asdict(process_packet(1.0, raw, 7))
    b = dataclasses.asdict(Pipeline({"unknown_policy": policy}).process(1.0, raw, 7))

    for key in ("preprocess_status", "processing_action", "flow_id", "direction", "flow_state"):   # added by Part 2 stages
        b.pop(key), a.pop(key)

    assert a == b


def test_unknown_app_payload_is_logged_or_ignored_by_policy():
    assert Pipeline({"unknown_policy": "log"}).process(1.0, b"XtZZZ", 1).app_protocol == "UNKNOWN"
    assert Pipeline({"unknown_policy": "skip"}).process(1.0, b"XtZZZ", 1).status == "IGNORED"


def test_cfg_policy_is_case_insensitive_and_overrides_module_default(monkeypatch):
    monkeypatch.setattr(pl, "UNKNOWN_POLICY", "log")
    assert Pipeline({"unknown_policy": "SKIP"}).process(1.0, b"XtZZZ", 1).status == "IGNORED"


@pytest.mark.parametrize("cfg", [{}, {"unknown_policy": None}, None])
def test_missing_cfg_policy_falls_back_to_module_default(monkeypatch, cfg):
    monkeypatch.setattr(pl, "UNKNOWN_POLICY", "skip")
    assert Pipeline(cfg).process(1.0, b"XtZZZ", 1).status == "IGNORED"


@pytest.mark.parametrize("cfg", [None, 5, "x", []])
def test_non_dict_cfg_becomes_empty_dict(cfg):
    assert Pipeline(cfg).cfg == {}


def test_module_level_wrapper_reads_policy_at_call_time(monkeypatch):
    monkeypatch.setattr(pl, "UNKNOWN_POLICY", "skip")
    assert process_packet(1.0, b"XtZZZ", 1).status == "IGNORED"
    monkeypatch.setattr(pl, "UNKNOWN_POLICY", "log")
    assert process_packet(1.0, b"XtZZZ", 1).status == "OK"


def test_pipeline_owns_a_tracker_wired_to_its_config_and_loggers():
    ev_log, fl_log = object(), object()
    p = Pipeline({"flow": {}}, event_logger=ev_log, flow_logger=fl_log)
    assert isinstance(p.flow_tracker, FlowTracker)
    assert p.flow_tracker.cfg is p.cfg
    assert (p.event_logger, p.flow_logger) == (ev_log, fl_log)


def test_two_pipelines_do_not_share_state():
    a, b = Pipeline({}), Pipeline({})
    assert a.flow_tracker is not b.flow_tracker
    assert a.flow_tracker.table is not b.flow_tracker.table

def _flow():
    return Flow(flow_id="x", protocol="UDP", endpoint_a={"ip": "1", "port": 1},
                endpoint_b={"ip": "2", "port": 2}, start_time=1.0, last_seen=2.0, state="ACTIVE")


def test_exported_flow_reaches_a_logger_with_log_method():
    got = []
    Pipeline({}, flow_logger=NS(log=got.append))._on_flow_export(_flow())
    assert len(got) == 1


def test_exported_flow_reaches_a_plain_callable_and_none_is_ignored():
    got = []
    Pipeline({}, flow_logger=got.append)._on_flow_export(_flow())
    Pipeline({})._on_flow_export(_flow())
    assert len(got) == 1


def test_failing_flow_logger_does_not_break_the_tracker():
    def boom(_):
        raise RuntimeError("disk full")

    p = Pipeline({"flow": {"udp_idle_timeout_sec": 1}}, flow_logger=boom)
    mk = lambda ts, sp: NS(timestamp=ts, transport_protocol="UDP", src_ip="a", dst_ip="b", src_port=sp,
                           dst_port=1, preprocess_status="valid", raw_length=1, payload=b"",
                           transport_fields={})
    p.flow_tracker.update(mk(0, 1))
    p.flow_tracker.update(mk(50, 2))
    assert p.flow_tracker.active_flow_count() == 1