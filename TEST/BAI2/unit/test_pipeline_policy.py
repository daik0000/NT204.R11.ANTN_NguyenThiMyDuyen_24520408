import pytest

from src.models.event import IDSEvent
from src.pipeline import pipeline as pl
from src.pipeline.pipeline import Pipeline


class Sink:
    """Records (record, flow_id_at_write_time) so the test can tell when a record was written."""
    def __init__(self):
        self.rows = []

    def log(self, record):
        self.rows.append((record, getattr(record, "flow_id", "n/a")))

    @property
    def records(self):
        return [r for r, _ in self.rows]


@pytest.fixture(autouse=True)
def fake_layers(monkeypatch):
    # raw = b"X" + sport + dport + payload   (ports are single bytes, enough to build distinct flows)
    def ipv4(raw):
        return {"status": "OK", "network_protocol": "IPv4", "src_ip": f"10.0.0.{raw[1]}",
                "dst_ip": f"10.0.0.{raw[2]}", "network_fields": {"ip_proto_number": 17},
                "transport_payload": raw[1:]}

    def udp(p):
        return {"status": "OK", "transport_protocol": "UDP", "src_port": p[0], "dst_port": p[1],
                "transport_fields": {}, "app_payload": p[2:]}

    monkeypatch.setattr(pl, "parse_ipv4", ipv4)
    monkeypatch.setattr(pl, "parse_udp", udp)
    monkeypatch.setattr(pl, "detect_application_protocol",
                        lambda **kw: ("HTTP", "payload") if kw["payload"].startswith(b"G") else ("UNKNOWN", "none"))
    monkeypatch.setattr(pl, "parse_http", lambda p: {"status": "OK", "app_protocol": "HTTP", "app_fields": {}})
    monkeypatch.setattr(pl, "decode_event", lambda e, c: e)

    def pre(e, c):
        p = e.payload or b""
        verdict = {b"S": ("valid", "skipped"), b"D": ("invalid", "dropped"), b"I": ("invalid", "flagged"),
                   b"F": ("valid", "flagged")}.get(p[:1], ("valid", "none"))
        e.preprocess_status, e.processing_action = verdict
        return e

    monkeypatch.setattr(pl, "preprocess_event", pre)


def pk(payload=b"Gx", sp=1, dp=2):
    return b"X" + bytes([sp, dp]) + payload


def mk(cfg=None):
    ev, fl = Sink(), Sink()
    return Pipeline(cfg or {}, event_logger=ev, flow_logger=fl), ev, fl


def test_normal_event_is_tracked_then_written_with_flow_fields():
    p, ev, fl = mk()
    e = p.process(1.0, pk(), 1)
    assert p.flow_tracker.active_flow_count() == 1
    assert len(ev.rows) == 1 and ev.rows[0][1] == e.flow_id and e.flow_id is not None
    assert e.direction == "forward" and e.flow_state == "ACTIVE"


@pytest.mark.parametrize("payload,action", [(b"Sx", "skipped"), (b"Dx", "dropped")])
def test_skipped_and_dropped_events_are_neither_tracked_nor_written(payload, action):
    p, ev, fl = mk()
    e = p.process(1.0, pk(payload), 1)
    assert e.processing_action == action
    assert p.flow_tracker.active_flow_count() == 0 and ev.rows == []
    assert (e.flow_id, e.direction, e.flow_state) == (None, None, None)


def test_skipped_event_does_not_move_the_tracker_clock():
    p, ev, fl = mk()
    p.process(500.0, pk(b"Sx"), 1)
    assert p.flow_tracker.clock == 0.0


def test_invalid_flagged_event_is_written_but_not_tracked():
    p, ev, fl = mk()
    e = p.process(1.0, pk(b"Ix"), 1)
    assert p.flow_tracker.active_flow_count() == 0
    assert ev.records == [e] and e.flow_id is None and e.processing_action == "flagged"


def test_unknown_app_payload_with_log_policy_is_tracked_and_written():
    p, ev, fl = mk({"unknown_policy": "log"})
    e = p.process(1.0, pk(b"zzz"), 1)
    assert e.app_protocol == "UNKNOWN"
    assert p.flow_tracker.active_flow_count() == 1 and ev.records == [e]


def test_unknown_app_payload_with_skip_policy_is_tracked_but_not_written():
    p, ev, fl = mk({"unknown_policy": "skip"})
    e = p.process(1.0, pk(b"zzz"), 1)
    assert e.status == "IGNORED"
    assert p.flow_tracker.active_flow_count() == 1 and ev.rows == []
    assert e.flow_id is not None


def test_ignored_event_is_never_written_even_if_flagged():
    p, ev, fl = mk({"unknown_policy": "skip"})
    p.process(1.0, pk(b"Fzz"), 1)          # IGNORED by Part 1 policy, 'flagged' by the preprocessor
    assert ev.rows == []


def test_flagged_event_that_is_not_ignored_is_written():
    p, ev, fl = mk()
    e = p.process(1.0, pk(b"F"), 1)
    assert ev.records == [e]


def test_both_directions_share_one_flow():
    p, ev, fl = mk()
    a = p.process(1.0, pk(sp=10, dp=20), 1)
    b = p.process(1.1, pk(sp=20, dp=10), 2)
    assert a.flow_id == b.flow_id and (a.direction, b.direction) == ("forward", "backward")
    assert p.flow_tracker.active_flow_count() == 1


def test_expired_flow_reaches_the_flow_logger():
    p, ev, fl = mk({"flow": {"udp_idle_timeout_sec": 5, "sweep_interval_sec": 1}})
    p.process(1.0, pk(sp=1), 1)
    p.process(50.0, pk(sp=2), 2)
    assert [f.close_reason for f in fl.records] == ["idle_timeout"]


def test_flush_sends_remaining_flows_to_flow_logger():
    p, ev, fl = mk()
    p.process(1.0, pk(sp=1), 1)
    p.process(2.0, pk(sp=2), 2)
    assert p.flush() == 2 and [f.close_reason for f in fl.records] == ["flush", "flush"]
    assert p.flush() == 0


def test_failing_event_logger_never_breaks_process():
    class Bad:
        def log(self, r):
            raise OSError("disk full")

    p = Pipeline({}, event_logger=Bad(), flow_logger=Bad())
    e = p.process(1.0, pk(), 1)
    assert isinstance(e, IDSEvent) and e.flow_id is not None


def test_pipeline_without_loggers_still_works():
    p = Pipeline({})
    assert p.process(1.0, pk(), 1).flow_id is not None and p.flush() == 1


def test_tracker_crash_is_isolated_and_event_is_still_written(monkeypatch):
    p, ev, fl = mk()

    def boom(event):
        raise RuntimeError("tracker down")

    monkeypatch.setattr(p.flow_tracker, "update", boom)
    e = p.process(1.0, pk(), 1)
    assert ev.records == [e] and e.flow_id is None
    assert e.error_info["layer"] == "flow_tracker"


def test_flush_exception_is_swallowed(monkeypatch):
    p, ev, fl = mk()

    def boom():
        raise RuntimeError("x")

    monkeypatch.setattr(p.flow_tracker, "flush", boom)
    assert p.flush() == 0