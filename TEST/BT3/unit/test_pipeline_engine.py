import copy
import dataclasses
import json

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether

from pcap_builder import tcp_packet, udp_packet
from src.pipeline.pipeline import Pipeline
from src.utils.config import load_config

GET = b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"


class Sink:
    """A logger that keeps what it is given, like JSONLLogger would write it."""

    def __init__(self):
        self.items = []
        self.closed = False

    def log(self, item):
        self.items.append(item)

    def close(self):
        self.closed = True


def write_rules(tmp_path, *lines, name="t.rules"):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def rule(sid, options="", header="alert tcp any any -> any 80"):
    return f'{header} (msg:"r{sid}"; {options} sid:{sid};)'


def make_cfg(rule_files, **engine):
    cfg = copy.deepcopy(load_config())
    cfg["engine"]["rule_files"] = [{"path": f, "enabled": True} for f in rule_files]
    cfg["engine"].update(engine)
    return cfg


def session(payload=GET):
    return [
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "S", ts=1.0),
        tcp_packet("10.0.0.2", 80, "10.0.0.1", 40000, "SA", ts=1.1),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "A", ts=1.2),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "PA", ts=1.3, payload=payload),
    ]


def run(cfg, frames, **kw):
    events, detections = Sink(), Sink()
    pipe = Pipeline(cfg, event_logger=events, detection_logger=detections, **kw)
    for i, frame in enumerate(frames, start=1):
        pipe.process(frame.time, bytes(frame), i)
    return pipe, events.items, detections.items


# --- detections --------------------------------------------------------------------------------------------------------

def test_detections_are_written_for_the_packet_that_matches(tmp_path):
    f = write_rules(tmp_path,
                    rule(10, 'flow:to_server,established; content:"../";'),
                    rule(20, 'content:"zzz";'),
                    rule(30, "flags:PA; dsize:>10;"))
    pipe, events, detections = run(make_cfg([f]), session())
    assert [d.sid for d in detections] == [10, 30]
    assert all(d.packet_id == 4 for d in detections)
    assert detections[0].flow_direction == "to_server" and detections[0].flow_id == events[3].flow_id
    assert pipe.detections_written == 2 and pipe.engine.stats.matches == 2
    assert len(events) == 4                         # every packet is still logged as an event


def test_each_detection_is_written_as_json_by_the_real_logger(tmp_path):
    from src.logging.jsonl_logger import JSONLLogger
    f = write_rules(tmp_path, rule(10, 'content:"../";'))
    out = tmp_path / "out" / "detections.jsonl"
    with JSONLLogger(file_path=str(out)) as det_log:
        pipe = Pipeline(make_cfg([f]), detection_logger=det_log)
        for i, frame in enumerate(session(), start=1):
            pipe.process(frame.time, bytes(frame), i)
    (line,) = out.read_text(encoding="utf-8").splitlines()
    row = json.loads(line)
    assert (row["sid"], row["packet_id"], row["protocol"], row["matched"]) == (
        10, 4, "TCP", [{"keyword": "content", "value": "../", "offset": 5, "length": 3}])


def test_the_engine_runs_after_the_flow_tracker_so_established_is_up_to_date(tmp_path):
    f = write_rules(tmp_path, rule(1, "flow:established;"), rule(2, "flow:not_established;"))
    _, _, detections = run(make_cfg([f]), session())
    assert [(d.packet_id, d.sid) for d in detections] == [(1, 2), (3, 1), (4, 1)]


# --- Part 2 behaviour is untouched ------------------------------------------------------------------------------------------

def snapshot(events):
    return [json.dumps(dataclasses.asdict(e), default=str, sort_keys=True) for e in events]


def test_the_engine_does_not_change_any_event_field(tmp_path):
    f = write_rules(tmp_path, rule(10, 'content:"../";'), rule(20, "flags:PA;"), rule(30, "flow:established;"))
    frames = session()
    _, with_engine, detections = run(make_cfg([f]), frames)
    off = make_cfg([f], enabled=False)
    _, without_engine, none = run(off, frames)
    assert detections and none == []
    assert snapshot(with_engine) == snapshot(without_engine)                 # byte for byte


def test_engine_disabled_gives_exactly_the_part_2_pipeline(tmp_path):
    f = write_rules(tmp_path, rule(10))
    frames = session()
    _, off_events, off_detections = run(make_cfg([f], enabled=False), frames)
    cfg_no_engine = make_cfg([f])
    del cfg_no_engine["engine"]
    pipe, bare_events, bare_detections = run(cfg_no_engine, frames)
    assert pipe.engine is None and bare_detections == [] and off_detections == []
    assert snapshot(off_events) == snapshot(bare_events)


def test_a_cfg_without_engine_section_has_no_engine():
    pipe = Pipeline({})
    frame = session()[0]
    assert pipe.engine is None
    assert pipe.process(frame.time, bytes(frame), 1).packet_id == 1


def test_no_rules_the_pipeline_keeps_running(tmp_path):
    pipe, events, detections = run(make_cfg([str(tmp_path / "missing.rules")]), session())
    assert len(events) == 4 and detections == [] and pipe.engine.rule_count == 0


# --- skipped / ignored / unknown -------------------------------------------------------------------------------------------------

def icmp_frame():
    frame = Ether(src="02:00:0a:00:00:01", dst="02:00:0a:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    frame.time = 1.0
    return frame


def test_a_skipped_event_is_counted_once_by_the_engine_and_never_matched(tmp_path):
    f = write_rules(tmp_path, rule(1, header="alert ip any any -> any any"))
    cfg = make_cfg([f])
    cfg["preprocessor"]["unsupported_policy"] = "skip"
    events, detections = Sink(), Sink()
    pipe = Pipeline(cfg, event_logger=events, detection_logger=detections)
    out = pipe.process(1.0, bytes(icmp_frame()), 1)
    assert out.processing_action == "skipped" and events.items == []          # not logged: Part 2 policy
    assert detections.items == []
    assert (pipe.engine.stats.events_skipped, pipe.engine.stats.events_evaluated) == (1, 0)


def test_a_dropped_event_is_counted_as_skipped_by_the_engine(tmp_path):
    f = write_rules(tmp_path, rule(1, header="alert ip any any -> any any"))
    cfg = make_cfg([f])
    cfg["preprocessor"]["invalid_policy"] = "drop"
    pipe = Pipeline(cfg, event_logger=Sink(), detection_logger=Sink())
    out = pipe.process(1.0, b"\x00" * 5, 1)                  # not even IPv4
    assert out.processing_action in ("dropped", "skipped")
    assert pipe.engine.stats.events_skipped == 1 and pipe.detection_logger.items == []


def test_a_logged_icmp_event_has_no_ports_so_the_engine_skips_it(tmp_path):
    f = write_rules(tmp_path, rule(1, header="alert ip any any -> any any"))
    events, detections = Sink(), Sink()
    pipe = Pipeline(make_cfg([f]), event_logger=events, detection_logger=detections)
    out = pipe.process(1.0, bytes(icmp_frame()), 1)
    assert out.transport_protocol is None
    assert detections.items == [] and pipe.engine.stats.events_skipped == 1


@pytest.mark.parametrize("policy, status", [("log", "OK"), ("skip", "IGNORED")])
def test_unknown_application_protocol_still_matches(tmp_path, policy, status):
    f = write_rules(tmp_path, rule(1, 'content:"../";', header="alert udp any any -> any 9999"))
    cfg = make_cfg([f])
    cfg["unknown_policy"] = policy
    frame = udp_packet("10.0.0.1", 40000, "10.0.0.2", 9999, ts=1.0, payload=b"hello ../ world")
    detections = Sink()
    pipe = Pipeline(cfg, detection_logger=detections)
    out = pipe.process(frame.time, bytes(frame), 1)
    assert out.status == status                      # IGNORED only means "do not write the event"
    assert [d.sid for d in detections.items] == [1]
    assert detections.items[0].matched[0]["offset"] == 6


# --- errors ------------------------------------------------------------------------------------------------------------------------------

def test_an_engine_crash_is_recorded_and_the_event_still_goes_on(tmp_path, monkeypatch):
    f = write_rules(tmp_path, rule(1, 'content:"GET";'))
    events, detections = Sink(), Sink()
    pipe = Pipeline(make_cfg([f]), event_logger=events, detection_logger=detections)
    monkeypatch.setattr(pipe.engine, "process", lambda event: (_ for _ in ()).throw(RuntimeError("engine bug")))
    for i, frame in enumerate(session(), start=1):
        out = pipe.process(frame.time, bytes(frame), i)
    assert len(events.items) == 4 and detections.items == []
    assert out.error_info == {"layer": "engine", "detail": "engine bug"}
    assert out.flow_id is not None                           # the Flow Tracker's work is intact


def test_an_earlier_error_info_is_not_overwritten(tmp_path, monkeypatch):
    f = write_rules(tmp_path, rule(1))
    pipe = Pipeline(make_cfg([f]), event_logger=Sink())
    monkeypatch.setattr(pipe.engine, "process", lambda event: (_ for _ in ()).throw(RuntimeError("late")))
    # a truncated TCP segment: the parser sets error_info first
    frame = tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "S", ts=1.0)
    raw = bytes(frame)[:14 + 20 + 8]
    out = pipe.process(1.0, raw, 1)
    assert out.status == "MALFORMED"
    assert out.error_info is not None and out.error_info.get("layer") != "engine"


def test_a_failing_detection_logger_does_not_stop_the_pipeline(tmp_path):
    class Broken:
        def log(self, item):
            raise OSError("disk full")

    f = write_rules(tmp_path, rule(1, 'content:"GET";'))
    events = Sink()
    pipe = Pipeline(make_cfg([f]), event_logger=events, detection_logger=Broken())
    for i, frame in enumerate(session(), start=1):
        pipe.process(frame.time, bytes(frame), i)
    assert len(events.items) == 4 and pipe.detections_written == 0 and pipe.engine.stats.matches == 1


def test_a_missing_rules_file_stops_the_start_up(tmp_path):
    with pytest.raises(FileNotFoundError):
        Pipeline(make_cfg([]), extra_rule_paths=[str(tmp_path / "nope.rules")])


def test_extra_rule_paths_are_loaded(tmp_path):
    x = write_rules(tmp_path, rule(5, 'content:"GET";'), name="x.rules")
    pipe, _, detections = run(make_cfg([]), session(), extra_rule_paths=[x])
    assert [d.sid for d in detections] == [5]


def test_close_closes_the_detection_logger_too(tmp_path):
    events, flows, detections = Sink(), Sink(), Sink()
    pipe = Pipeline(make_cfg([]), event_logger=events, flow_logger=flows, detection_logger=detections)
    pipe.close()
    assert events.closed and flows.closed and detections.closed


def test_when_the_flow_tracker_fails_the_engine_sees_no_flow(tmp_path, monkeypatch):
    f = write_rules(tmp_path, rule(1, "flow:established;"), rule(2, 'content:"GET";'))
    events, detections = Sink(), Sink()
    pipe = Pipeline(make_cfg([f]), event_logger=events, detection_logger=detections)
    frames = session()
    for i, frame in enumerate(frames[:3], start=1):
        pipe.process(frame.time, bytes(frame), i)             # an established flow is in the table
    monkeypatch.setattr(pipe.flow_tracker, "update", lambda event: (_ for _ in ()).throw(RuntimeError("tracker bug")))
    out = pipe.process(frames[3].time, bytes(frames[3]), 4)
    assert out.flow_id is None and out.error_info["layer"] == "flow_tracker"
    assert [d.sid for d in detections.items if d.packet_id == 4] == [2]     # no flow: rule 1 stays silent


# --- rules_report.jsonl and detections.jsonl as files -------------------------------------------------------------------

def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def test_rules_report_is_written_once_at_start_up_with_every_rule_line(tmp_path):
    f = write_rules(tmp_path, "# comment", rule(1, 'content:"GET";'), "garbage",
                    'alert icmp any any -> any any (msg:"i"; sid:3;)', rule(4), rule(5))
    out = tmp_path / "reports" / "rules_report.jsonl"
    cfg = make_cfg([f], disabled_sids=[4])
    Pipeline(cfg, rules_report_path=str(out))
    rows = read_jsonl(out)                                        # before any packet is processed
    assert [(r["line"], r["status"], r["reason"], r["sid"]) for r in rows] == [
        (2, "valid", None, 1),
        (3, "invalid", "invalid:malformed_rule", None),
        (4, "unsupported", "unsupported:protocol:icmp", 3),
        (5, "disabled", "disabled:sid", 4),
        (6, "valid", None, 5),
    ]
    assert rows[0]["file"] == f and rows[1]["text"] == "garbage"
    assert set(rows[0]) == {"file", "line", "status", "reason", "sid", "text"}


def test_processing_packets_never_touches_the_rules_report(tmp_path):
    f = write_rules(tmp_path, rule(1, 'content:"GET";'))
    out = tmp_path / "rules_report.jsonl"
    pipe = Pipeline(make_cfg([f]), detection_logger=Sink(), rules_report_path=str(out))
    before = out.read_text(encoding="utf-8")
    for i, frame in enumerate(session(), start=1):
        pipe.process(frame.time, bytes(frame), i)
    pipe.flush()
    pipe.close()
    assert out.read_text(encoding="utf-8") == before and len(before.splitlines()) == 1


def test_the_rules_report_is_replaced_on_each_run(tmp_path):
    f = write_rules(tmp_path, rule(1), rule(2))
    out = tmp_path / "rules_report.jsonl"
    Pipeline(make_cfg([f]), rules_report_path=str(out))
    Pipeline(make_cfg([f]), rules_report_path=str(out))
    assert len(read_jsonl(out)) == 2


def test_engine_with_no_rules_still_writes_an_empty_report(tmp_path):
    out = tmp_path / "rules_report.jsonl"
    Pipeline(make_cfg([]), rules_report_path=str(out))
    assert out.exists() and out.read_text() == ""


def test_no_report_when_the_engine_is_disabled_or_absent(tmp_path):
    f = write_rules(tmp_path, rule(1))
    off, bare = tmp_path / "off.jsonl", tmp_path / "bare.jsonl"
    Pipeline(make_cfg([f], enabled=False), rules_report_path=str(off))
    cfg = make_cfg([f])
    del cfg["engine"]
    Pipeline(cfg, rules_report_path=str(bare))
    assert not off.exists() and not bare.exists()


def test_no_report_path_means_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = write_rules(tmp_path, rule(1))
    Pipeline(make_cfg([f]))
    assert not (tmp_path / "output").exists() and not (tmp_path / "rules_report.jsonl").exists()


def test_a_report_that_cannot_be_written_is_only_a_warning(tmp_path, caplog):
    import logging
    f = write_rules(tmp_path, rule(1, 'content:"GET";'))
    unwritable = tmp_path                                          # a directory, not a file
    with caplog.at_level(logging.WARNING):
        events, detections = Sink(), Sink()
        pipe = Pipeline(make_cfg([f]), event_logger=events, detection_logger=detections,
                        rules_report_path=str(unwritable))
        for i, frame in enumerate(session(), start=1):
            pipe.process(frame.time, bytes(frame), i)
    assert any("rule report" in m.lower() for m in caplog.messages)
    assert len(events.items) == 4 and [d.sid for d in detections.items] == [1]


def test_a_detection_is_written_as_soon_as_it_is_produced_and_flush_changes_nothing(tmp_path):
    f = write_rules(tmp_path, rule(1, 'content:"GET";'))
    detections = Sink()
    pipe = Pipeline(make_cfg([f]), detection_logger=detections)
    frames = session()
    for i, frame in enumerate(frames[:3], start=1):
        pipe.process(frame.time, bytes(frame), i)
    assert detections.items == []
    pipe.process(frames[3].time, bytes(frames[3]), 4)
    assert len(detections.items) == 1                              # visible before flush() or close()
    pipe.flush()
    assert len(detections.items) == 1 and not detections.closed
    pipe.close()
    assert detections.closed


def test_detections_jsonl_has_one_line_per_detection_and_rules_report_is_separate(tmp_path):
    from src.logging.jsonl_logger import JSONLLogger
    f = write_rules(tmp_path, rule(10, 'content:"../";'), rule(20, "flags:PA;"), rule(30, 'content:"zzz";'))
    det_path, rep_path = tmp_path / "det.jsonl", tmp_path / "rep.jsonl"
    with JSONLLogger(file_path=str(det_path)) as det_log:
        with Pipeline(make_cfg([f]), detection_logger=det_log, rules_report_path=str(rep_path)) as pipe:
            for i, frame in enumerate(session(), start=1):
                pipe.process(frame.time, bytes(frame), i)
    detections, report = read_jsonl(det_path), read_jsonl(rep_path)
    assert [d["sid"] for d in detections] == [10, 20]
    assert len(report) == 3 and {r["status"] for r in report} == {"valid"}
    assert all("status" not in d for d in detections)


def test_closing_a_jsonl_logger_twice_is_safe(tmp_path):
    # Pipeline.close() and the surrounding `with` both close the detection logger
    from src.logging.jsonl_logger import JSONLLogger
    log = JSONLLogger(file_path=str(tmp_path / "d.jsonl"))
    log.close()
    log.close()
    with JSONLLogger(file_path=str(tmp_path / "e.jsonl")) as other:
        other.close()                                              # closed inside, closed again by `with`
