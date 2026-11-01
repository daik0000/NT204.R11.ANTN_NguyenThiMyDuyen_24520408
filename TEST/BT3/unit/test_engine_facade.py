import copy
import logging

import pytest

from pcap_builder import tcp_packet
from src.engine.engine import Engine, engine_enabled
from src.flow.tracker import FlowTracker
from src.models.detection import Detection
from src.pipeline.pipeline import _parse_packet_layers
from src.utils.config import DEFAULT_CONFIG

GET = b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"
HEAD = "alert tcp any any -> any 80"


def write(tmp_path, name, *lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def rule(sid, options="", header=HEAD):
    return f'{header} (msg:"r{sid}"; {options} sid:{sid};)'


def make_cfg(files, disabled_sids=(), enabled=True):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["engine"]["rule_files"] = [{"path": f, "enabled": True} for f in files]
    cfg["engine"]["disabled_sids"] = list(disabled_sids)
    cfg["engine"]["enabled"] = enabled
    cfg["ports"] = {80: "HTTP"}
    return cfg


def event_of(frame, packet_id=1):
    return _parse_packet_layers(frame.time, bytes(frame), packet_id)


def feed(tracker, engine, *frames):
    """update() the tracker with each frame, then process(); returns the detections of the last one."""
    out = []
    for i, frame in enumerate(frames, start=1):
        event = event_of(frame, i)
        tracker.update(event)
        out = engine.process(event)
    return out


def session(payload=GET):
    return [
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "S", ts=1.0),
        tcp_packet("10.0.0.2", 80, "10.0.0.1", 40000, "SA", ts=1.1),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "A", ts=1.2),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "PA", ts=1.3, payload=payload),
    ]


# --- set-up: load -> parse -> repository -> index -------------------------------------------------------------------

def test_loads_rules_from_every_file_in_order_and_keeps_the_report(tmp_path):
    a = write(tmp_path, "a.rules", "# comment", rule(30, 'content:"GET";'), "this is not a rule", rule(10, "flags:PA;"))
    b = write(tmp_path, "b.rules", rule(20, 'content:"../";'), "alert icmp any any -> any any (msg:\"i\"; sid:99;)")
    eng = Engine(make_cfg([a, b]), FlowTracker({}))
    assert [r.sid for r in eng.repository.all()] == [30, 10, 20]
    assert eng.repository.frozen and eng.rule_count == 3 and eng.enabled
    rep = eng.report
    assert (rep.valid, rep.invalid, rep.unsupported, rep.disabled, rep.files_failed) == (3, 1, 1, 0, 0)
    assert [(rec.status, rec.line) for rec in eng.records if rec.file == b] == [("valid", 1), ("unsupported", 2)]
    assert eng.records[1].reason == "invalid:malformed_rule" and eng.records[1].sid is None


def test_disabled_sids_are_recorded_and_not_active(tmp_path):
    f = write(tmp_path, "a.rules", rule(1), rule(2), rule(3))
    eng = Engine(make_cfg([f], disabled_sids=[2]), FlowTracker({}))
    assert [r.sid for r in eng.repository.all()] == [1, 3]
    assert eng.report.disabled == 1 and [rec.status for rec in eng.records] == ["valid", "disabled", "valid"]


def test_duplicate_sid_across_files_keeps_the_first(tmp_path):
    a = write(tmp_path, "a.rules", rule(1, 'content:"GET";'))
    b = write(tmp_path, "b.rules", rule(1, 'content:"zzz";'))
    eng = Engine(make_cfg([a, b]), FlowTracker({}))
    assert eng.rule_count == 1 and eng.records[1].reason == "invalid:duplicate_sid"


def test_extra_rule_paths_are_loaded_after_the_configured_files(tmp_path):
    a = write(tmp_path, "a.rules", rule(1))
    x = write(tmp_path, "x.rules", rule(2))
    eng = Engine(make_cfg([a]), FlowTracker({}), extra_rule_paths=[x])
    assert [r.sid for r in eng.repository.all()] == [1, 2]


def test_a_missing_extra_rule_path_is_an_error_at_start(tmp_path):
    with pytest.raises(FileNotFoundError):
        Engine(make_cfg([]), FlowTracker({}), extra_rule_paths=[str(tmp_path / "nope.rules")])


def test_missing_config_file_warns_and_the_other_files_still_load(tmp_path, caplog):
    b = write(tmp_path, "b.rules", rule(1))
    with caplog.at_level(logging.WARNING):
        eng = Engine(make_cfg([str(tmp_path / "gone.rules"), b]), FlowTracker({}))
    assert eng.rule_count == 1 and eng.report.files_failed == 1
    assert any("gone.rules" in m for m in caplog.messages)


# --- always valid ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("files", [[], ["__missing__"]])
def test_no_active_rule_means_process_returns_nothing(tmp_path, files):
    files = [str(tmp_path / "missing.rules") if f == "__missing__" else f for f in files]
    eng = Engine(make_cfg(files), FlowTracker({}))
    tracker = FlowTracker({})
    assert eng.rule_count == 0
    assert feed(tracker, eng, *session()) == []
    assert eng.stats.events_skipped == 4 and eng.stats.events_evaluated == 0


def test_only_rejected_rules_leave_a_working_engine(tmp_path):
    f = write(tmp_path, "bad.rules", "garbage", 'alert icmp any any -> any any (msg:"x"; sid:1;)',
              'alert tcp any any -> any 80 (msg:"x"; pcre:"/a/"; sid:2;)')
    eng = Engine(make_cfg([f]), FlowTracker({}))
    assert eng.rule_count == 0 and (eng.report.invalid, eng.report.unsupported) == (1, 2)
    assert feed(FlowTracker({}), eng, *session()) == []


def test_default_config_without_engine_section_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                      # no config/rules/local.rules here: just a warning
    eng = Engine({}, None)
    assert eng.enabled and eng.rule_count == 0 and eng.report.files_failed == 1
    assert eng.process(event_of(session()[0])) == []


def test_engine_section_with_missing_keys_uses_the_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = {"engine": {"enabled": True}}               # no rule_files, disabled_sids or default_priority
    eng = Engine(cfg, FlowTracker({}))
    assert eng.enabled and eng.rule_count == 0 and eng.report.files_failed == 1   # default path not found here
    (tmp_path / "config" / "rules").mkdir(parents=True)
    (tmp_path / "config" / "rules" / "local.rules").write_text(rule(7, 'content:"GET";') + "\n", encoding="utf-8")
    eng = Engine({"engine": {"disabled_sids": [99]}}, FlowTracker({}))
    assert [r.sid for r in eng.repository.all()] == [7] and eng.repository.all()[0].priority == 3


def test_engine_enabled_is_read_only():
    eng = Engine(make_cfg([]), FlowTracker({}))
    with pytest.raises(AttributeError):
        eng.enabled = False


def test_rules_option_is_ignored_with_a_warning_when_the_engine_is_off(tmp_path, caplog):
    x = write(tmp_path, "x.rules", rule(2))
    with caplog.at_level(logging.WARNING):
        eng = Engine(make_cfg([], enabled=False), FlowTracker({}), extra_rule_paths=[x])
    assert eng.rule_count == 0 and eng.records == []
    assert any("--rules ignored" in m for m in caplog.messages)


def test_a_missing_rules_file_is_still_an_error_when_the_engine_is_off(tmp_path):
    with pytest.raises(FileNotFoundError):
        Engine(make_cfg([], enabled=False), FlowTracker({}), extra_rule_paths=[str(tmp_path / "nope.rules")])


def test_engine_disabled_loads_nothing_and_returns_nothing(tmp_path):
    f = write(tmp_path, "a.rules", rule(1))
    eng = Engine(make_cfg([f, str(tmp_path / "gone.rules")], enabled=False), FlowTracker({}),
                 extra_rule_paths=None)
    assert not eng.enabled and eng.rule_count == 0
    assert eng.records == [] and eng.report.to_dict() == dict.fromkeys(eng.report.to_dict(), 0)
    assert eng.process(event_of(session()[3])) == []
    assert eng.stats.events_skipped == 1


# --- process ---------------------------------------------------------------------------------------------------------------------------------------

def test_process_returns_detections_in_rule_order_with_flow_context(tmp_path):
    f = write(tmp_path, "a.rules",
              rule(10, 'flow:to_server,established; content:"../";'),
              rule(20, 'content:"zzz";'),
              rule(30, 'flags:PA; dsize:>10;'),
              rule(40, 'flow:to_client;'),
              rule(50, 'content:"PASSWD"; nocase; content:"HTTP"; distance:1;'))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    detections = feed(tracker, eng, *session())
    assert [d.sid for d in detections] == [10, 30, 50]
    assert all(isinstance(d, Detection) for d in detections)
    first = detections[0]
    assert (first.flow_direction, first.protocol, first.dst_port, first.packet_id) == ("to_server", "TCP", 80, 4)
    assert first.matched == [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]
    assert first.flow_id and detections[1].matched == [{"keyword": "header"}]
    assert eng.stats.matches == 3 and eng.stats.is_consistent()


def test_flow_established_depends_on_the_tracker_state_after_this_packet(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:established;"), rule(2, "flow:not_established;"))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    got = []
    for i, frame in enumerate(session(), start=1):
        event = event_of(frame, i)
        tracker.update(event)
        got.append([d.sid for d in eng.process(event)])
    assert got == [[2], [], [1], [1]]               # SYN: not established; SYN/ACK: no rule (dst port 40000); ACK, data: established


def test_without_a_tracker_rules_with_flow_never_match(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:established;"), rule(2, 'content:"GET";'))
    eng = Engine(make_cfg([f]), None)
    event = event_of(session()[3])
    assert [d.sid for d in eng.process(event)] == [2]


def test_process_only_reads_the_tracker(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:established;"))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    frames = session()
    for i, frame in enumerate(frames, start=1):
        tracker.update(event_of(frame, i))
    before = ([k for k, _ in tracker.table.items()], tracker.active_flow_count(), tracker.clock,
              [e.flow.packet_count for _, e in tracker.table.items()])
    eng.process(event_of(frames[3], 4))
    eng.process(event_of(frames[3], 4))
    after = ([k for k, _ in tracker.table.items()], tracker.active_flow_count(), tracker.clock,
             [e.flow.packet_count for _, e in tracker.table.items()])
    assert before == after


def test_ineligible_event_is_skipped_by_the_evaluator_and_counted_once(tmp_path):
    f = write(tmp_path, "a.rules", rule(1))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    event = event_of(session()[3])
    tracker.update(event)
    event.processing_action = "dropped"
    assert eng.process(event) == []
    assert eng.stats.events_skipped == 1 and eng.stats.events_evaluated == 0


def test_a_broken_rule_does_not_stop_the_others(tmp_path, monkeypatch):
    from src.engine import evaluator as evaluator_module
    f = write(tmp_path, "a.rules", rule(1, 'content:"GET";'), rule(2, 'content:"GET";'), rule(3, 'content:"../";'))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    real = evaluator_module.match_rule
    monkeypatch.setattr(evaluator_module, "match_rule",
                        lambda rl, *a, **k: (_ for _ in ()).throw(RuntimeError("x")) if rl.sid == 2 else real(rl, *a, **k))
    assert [d.sid for d in feed(tracker, eng, *session())] == [1, 3]
    assert eng.stats.rule_errors == 3              # rule 2 is a candidate for the 3 packets sent to port 80
    assert eng.stats.is_consistent()


def test_stats_and_summary(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, 'content:"GET";'), "bad line")
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    feed(tracker, eng, *session())
    line = eng.summary()
    assert "\n" not in line
    assert line.startswith("rules: loaded=1 invalid=1 unsupported=0 disabled=0 files_failed=0 | engine: ")
    assert "matches=1" in line


# --- events without a flow get no flow context ---------------------------------------------------------------------------

class SpyTracker:
    def __init__(self, real):
        self.real, self.snapshot_calls = real, 0

    def update(self, event):
        return self.real.update(event)

    def snapshot(self, event):
        self.snapshot_calls += 1
        return self.real.snapshot(event)


def test_an_event_without_flow_id_does_not_even_ask_the_tracker(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:established;"), rule(2, 'content:"GET";'))
    real = FlowTracker({})
    spy = SpyTracker(real)
    eng = Engine(make_cfg([f]), spy)
    frames = session()
    for i, frame in enumerate(frames, start=1):               # the tracker now holds the live flow
        real.update(event_of(frame, i))
    event = event_of(frames[3], 4)                            # same 5-tuple, but never tracked: flow_id is None
    assert event.flow_id is None
    assert [d.sid for d in eng.process(event)] == [2]         # rule 1 (flow:) cannot match, rule 2 can
    assert spy.snapshot_calls == 0


def test_a_tracker_failure_leaves_rules_with_flow_unmatched_and_others_working(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:established;"), rule(2, 'content:"GET";'))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    for i, frame in enumerate(session()[:3], start=1):
        tracker.update(event_of(frame, i))                    # an established flow exists
    event = event_of(session()[3], 4)
    event.flow_id = event.direction = event.flow_state = None  # what the pipeline sets when update() raised
    assert [d.sid for d in eng.process(event)] == [2]


def test_a_flow_with_a_different_id_than_the_event_is_not_used(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:established;"))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    event = event_of(session()[3], 4)
    tracker.update(event)
    event.flow_id = "some-other-flow"
    assert eng.process(event) == []


def test_tracked_event_still_gets_its_context(tmp_path):
    f = write(tmp_path, "a.rules", rule(1, "flow:to_server;"))
    tracker = FlowTracker({})
    eng = Engine(make_cfg([f]), tracker)
    assert [d.sid for d in feed(tracker, eng, *session()[:1])] == [1]


@pytest.mark.parametrize("cfg, expected", [
    (None, True), ({}, True), ({"engine": None}, True), ({"engine": {}}, True),
    ({"engine": {"enabled": True}}, True), ({"engine": {"enabled": False}}, False),
    ({"engine": {"rule_files": []}}, True),
])
def test_engine_enabled_is_decided_in_one_place(cfg, expected):
    assert engine_enabled(cfg) is expected
    assert Engine(cfg, None, None).enabled is expected               # the Engine and main.py cannot disagree
