import logging

import pytest

from pcap_builder import tcp_packet, udp_packet
from src.engine import evaluator as evaluator_module
from src.engine.flow_context import build_flow_context
from src.engine.evaluator import EvaluationEngine
from src.engine.stats import EvaluationStats
from src.flow.tracker import FlowTracker
from src.models.detection import Detection
from src.models.engine_types import FlowContext
from src.models.event import IDSEvent
from src.pipeline.pipeline import _parse_packet_layers
from src.rules.repository import RuleRepository
from src.rules.validator import parse_rule

GET = b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"


def make_repo(*lines):
    repo = RuleRepository()
    for line in lines:
        result = parse_rule(line)
        assert result.status == "valid", (line, result)
        repo.add(result.rule)
    return repo


def r(sid, options="", header="alert tcp any any -> any 80"):
    return f'{header} (msg:"r{sid}"; {options} sid:{sid};)'


def pkt(payload=GET, proto="TCP", dst_port=80, **kw):
    d = dict(packet_id=7, timestamp=1.0, src_ip="10.0.0.1", src_port=40000, dst_ip="10.0.0.2", dst_port=dst_port,
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=payload, transport_fields={"flags": ["PSH", "ACK"]} if proto == "TCP" else {})
    d.update(kw)
    return IDSEvent(**d)


def ctx(established=True, role="to_server"):
    return FlowContext(flow_id="f", protocol="TCP", state="ESTABLISHED" if established else "HANDSHAKE",
                       role=role, established=established, midstream=False, direction="forward")


def engine(*lines, cfg=None):
    return EvaluationEngine(make_repo(*lines), EvaluationStats(), cfg)


def sids(results):
    return [res.rule.sid for res in results]


# --- several rules match; no stop at the first -----------------------------------------------------------------

def test_every_matching_rule_is_returned_in_rule_order():
    eng = engine(r(30, 'content:"GET";'), r(10, 'content:"../";'), r(20, 'content:"nope";'), r(5, "flags:PA;"))
    results = eng.evaluate(pkt(), ctx())
    assert sids(results) == [30, 10, 5]                     # repository order, not sid order
    assert all(res.matched for res in results)
    assert (eng.stats.matches, eng.stats.candidate_rules, eng.stats.events_evaluated) == (3, 4, 1)


def test_results_carry_the_match_details():
    results = engine(r(1, 'content:"../";')).evaluate(pkt(), ctx())
    assert results[0].matches == [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]


def test_header_only_rule_matches_with_the_header_marker():
    results = engine(r(1)).evaluate(pkt(), ctx())
    assert results[0].matches == [{"keyword": "header"}]


def test_nothing_matches():
    eng = engine(r(1, 'content:"zzz";'), r(2, "flags:S;"))
    assert eng.evaluate(pkt(), ctx()) == []
    assert eng.stats.matches == 0 and eng.stats.is_consistent()


def test_only_indexer_candidates_are_tested():
    eng = engine(r(1), r(2, header="alert tcp any any -> any 8080"), r(3, header="alert udp any any -> any 80"))
    assert sids(eng.evaluate(pkt(), ctx())) == [1]
    assert eng.stats.candidate_rules == 1                  # rules 2 and 3 never left the index


def test_flow_context_is_used():
    eng = engine(r(1, "flow:established;"), r(2, "flow:not_established;"), r(3, "flow:to_client;"))
    assert sids(eng.evaluate(pkt(), ctx(established=True))) == [1]
    assert sids(eng.evaluate(pkt(), ctx(established=False))) == [2]
    assert sids(eng.evaluate(pkt(), None)) == []           # no context: rules with flow: never match


def test_bidirectional_rule_matches_a_packet_to_the_source_port():
    eng = engine(r(1, header="alert tcp any 80 <> any any"))
    assert sids(eng.evaluate(pkt(dst_port=40000, src_port=80), ctx())) == [1]


# --- error isolation ---------------------------------------------------------------------------------------------------

def failing_on(bad_sid, real=evaluator_module.match_rule):
    def wrapper(rule, event, ctx, content_fn, stats):
        if rule.sid == bad_sid:
            raise RuntimeError(f"bug in rule {bad_sid}")
        return real(rule, event, ctx, content_fn, stats)
    return wrapper


def test_a_failing_rule_does_not_stop_the_others(monkeypatch, caplog):
    eng = engine(r(1, 'content:"GET";'), r(2, 'content:"GET";'), r(3, 'content:"../";'))
    monkeypatch.setattr(evaluator_module, "match_rule", failing_on(2))
    with caplog.at_level(logging.WARNING):
        results = eng.evaluate(pkt(), ctx())
    assert sids(results) == [1, 3]                         # the rules around the broken one still match
    assert eng.stats.rule_errors == 1 and eng.stats.matches == 2
    assert eng.stats.is_consistent()
    assert any("sid=2" in m for m in caplog.messages)
    assert any(rec.exc_info for rec in caplog.records)


def test_two_matching_rules_and_one_failing_rule(monkeypatch):
    # the case from the issue: two rules match, one raises -> the others still match, rule_errors == 1
    eng = engine(r(1, 'content:"GET";'), r(2, 'content:"../";'), r(3, 'content:"HTTP";'))
    monkeypatch.setattr(evaluator_module, "match_rule", failing_on(2))
    results = eng.evaluate(pkt(), ctx())
    assert sids(results) == [1, 3] and eng.stats.rule_errors == 1


def test_a_rule_that_fails_in_its_content_search_counts_only_as_an_error(monkeypatch):
    def boom(rule, payload, lowered=None):
        if rule.sid == 2:
            raise ValueError("content bug")
        return real(rule, payload, lowered)

    real = evaluator_module.match_contents
    eng = engine(r(1, 'content:"GET";'), r(2, 'content:"GET";'), r(3, 'content:"zzz";'))
    monkeypatch.setattr(evaluator_module, "match_contents", boom)
    results = eng.evaluate(pkt(), ctx())
    s = eng.stats
    assert sids(results) == [1]
    assert (s.matches, s.rule_errors, s.rules_rejected_content, s.content_evaluations) == (1, 1, 1, 2)
    assert s.is_consistent()


def test_every_failing_rule_is_counted_once(monkeypatch):
    eng = engine(r(1), r(2), r(3))
    monkeypatch.setattr(evaluator_module, "match_rule", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    assert eng.evaluate(pkt(), ctx()) == []
    assert eng.stats.rule_errors == 3 and eng.stats.matches == 0 and eng.stats.is_consistent()


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
def test_base_exceptions_are_not_swallowed(monkeypatch, exc):
    eng = engine(r(1), r(2))

    def stop(*a, **k):
        raise exc()

    monkeypatch.setattr(evaluator_module, "match_rule", stop)
    with pytest.raises(exc):
        eng.evaluate(pkt(), ctx())
    assert eng.stats.rule_errors == 0


# --- skipped events ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    dict(processing_action="skipped"),
    dict(processing_action="dropped"),
    dict(preprocess_status="invalid"),
    dict(proto=None),
    dict(proto="ICMP"),
    dict(dst_port=None),
    dict(dst_port=True),
])
def test_ineligible_events_are_skipped_and_counted(kw):
    eng = engine(r(1))
    assert eng.evaluate(pkt(**kw), ctx()) == []
    assert (eng.stats.events_skipped, eng.stats.events_evaluated, eng.stats.candidate_rules) == (1, 0, 0)


def test_processed_but_normalised_events_are_evaluated():
    eng = engine(r(1))
    for action in ("normalized", "defaults_filled", "none", "flagged", None):
        assert sids(eng.evaluate(pkt(processing_action=action), ctx())) == [1]


def test_empty_repository_skips_every_event():
    eng = EvaluationEngine(RuleRepository(), EvaluationStats(), None)
    assert eng.evaluate(pkt(), ctx()) == [] and eng.stats.events_skipped == 1


def test_disabled_engine_skips_every_event():
    cfg = {"engine": {"enabled": False}}
    eng = engine(r(1), cfg=cfg)
    assert eng.enabled is False
    assert eng.evaluate(pkt(), ctx()) == []
    assert eng.stats.events_skipped == 1 and eng.stats.events_evaluated == 0


@pytest.mark.parametrize("cfg", [None, {}, {"engine": None}, {"engine": {}}, {"engine": {"enabled": True}}])
def test_engine_is_enabled_by_default(cfg):
    assert engine(r(1), cfg=cfg).enabled is True


# --- repository / index -----------------------------------------------------------------------------------------------------------

def test_engine_freezes_the_repository():
    repo = make_repo(r(1))
    assert repo.frozen is False
    EvaluationEngine(repo, EvaluationStats(), None)
    assert repo.frozen is True


def test_stats_object_is_shared_with_the_caller():
    stats = EvaluationStats()
    EvaluationEngine(make_repo(r(1)), stats, None).evaluate(pkt(), ctx())
    assert stats.matches == 1


def test_a_default_stats_object_is_created_when_none_is_given():
    eng = EvaluationEngine(make_repo(r(1)))
    eng.evaluate(pkt(), ctx())
    assert eng.stats.matches == 1


# --- payload handled once per packet -------------------------------------------------------------------------------------------------------

class Counting(bytes):
    calls = 0

    def lower(self):
        Counting.calls += 1
        return bytes.lower(self)


def test_payload_is_lower_cased_once_per_packet_however_many_nocase_rules():
    Counting.calls = 0
    eng = engine(r(1, 'content:"GET"; nocase;'), r(2, 'content:"ETC"; nocase;'), r(3, 'content:"http"; nocase;'))
    results = eng.evaluate(pkt(Counting(GET)), ctx())
    assert sids(results) == [1, 2, 3]
    assert Counting.calls == 1


def test_payload_is_not_lower_cased_when_no_rule_needs_it():
    Counting.calls = 0
    eng = engine(r(1, 'content:"GET";'), r(2, 'content:"../";'))
    assert sids(eng.evaluate(pkt(Counting(GET)), ctx())) == [1, 2]
    assert Counting.calls == 0


def test_bytearray_and_memoryview_payloads_work():
    eng = engine(r(1, 'content:"../"; nocase;'))
    assert sids(eng.evaluate(pkt(bytearray(GET)), ctx())) == [1]
    assert sids(eng.evaluate(pkt(memoryview(GET)), ctx())) == [1]


def test_empty_payload_rules_with_content_do_not_match():
    eng = engine(r(1, 'content:"GET";'), r(2))
    assert sids(eng.evaluate(pkt(b""), ctx())) == [2]


# --- log volume ---------------------------------------------------------------------------------------------------------------

def test_a_broken_rule_is_warned_once_but_counted_every_time(monkeypatch, caplog):
    eng = engine(r(1), r(2), r(3))
    monkeypatch.setattr(evaluator_module, "match_rule", failing_on(2))
    with caplog.at_level(logging.DEBUG, logger="src.engine.evaluator"):
        for _ in range(5):
            eng.evaluate(pkt(), ctx())
    warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING and "sid=2" in rec.getMessage()]
    debug = [rec for rec in caplog.records if rec.levelno == logging.DEBUG and "sid=2" in rec.getMessage()]
    assert len(warnings) == 1 and warnings[0].exc_info
    assert len(debug) == 4
    assert eng.stats.rule_errors == 5 and eng.stats.is_consistent()


def test_two_different_broken_rules_each_get_their_own_warning(monkeypatch, caplog):
    eng = engine(r(1), r(2))
    monkeypatch.setattr(evaluator_module, "match_rule", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    with caplog.at_level(logging.WARNING, logger="src.engine.evaluator"):
        eng.evaluate(pkt(), ctx())
        eng.evaluate(pkt(), ctx())
    assert sorted(rec.getMessage().split()[1] for rec in caplog.records) == ["sid=1", "sid=2"]


# --- IGNORED / UNKNOWN events are still evaluated -------------------------------------------------------------------------------------

@pytest.mark.parametrize("policy, status, app", [("log", "OK", "UNKNOWN"), ("skip", "IGNORED", None)])
def test_udp_on_a_port_without_a_parser_still_matches(policy, status, app, tmp_path):
    frame = udp_packet("10.0.0.1", 40000, "10.0.0.2", 9999, ts=1.0, payload=b"hello ../ world")
    event = _parse_packet_layers(1.0, bytes(frame), 1, unknown_policy=policy)
    assert (event.status, event.app_protocol) == (status, app)
    eng = engine(r(1, 'content:"../";', header="alert udp any any -> any 9999"))
    results = eng.evaluate(event, None)
    assert sids(results) == [1]
    assert results[0].matches == [{"keyword": "content", "value": "../", "offset": 6, "length": 3}]
    assert eng.stats.events_skipped == 0


# --- T13-style: real FlowTracker, several rules, one packet ---------------------------------------------------------------------------------

def test_t13_one_packet_triggers_three_rules_in_order():
    tracker = FlowTracker({})
    cfg = {"ports": {80: "HTTP"}}
    eng = EvaluationEngine(make_repo(
        r(10, 'flow:to_server,established; content:"../";'),           # matches
        r(20, 'content:"zzz";'),                                        # content fails
        r(30, 'flags:PA; dsize:>10;'),                                  # matches (header + packet only)
        r(40, 'flow:to_client;'),                                       # flow fails
        r(50, 'content:"PASSWD"; nocase; content:"HTTP"; distance:1;'),  # matches, relative content
        r(60, header="alert tcp any any -> any 8080"),                  # never a candidate
    ), EvaluationStats(), cfg)

    packets = [
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "S", ts=1.0),
        tcp_packet("10.0.0.2", 80, "10.0.0.1", 40000, "SA", ts=1.1),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "A", ts=1.2),
        tcp_packet("10.0.0.1", 40000, "10.0.0.2", 80, "PA", ts=1.3, payload=GET),
    ]
    last = None
    for frame in packets:
        event = _parse_packet_layers(frame.time, bytes(frame), 1)
        tracker.update(event)
        flow_ctx = build_flow_context(event, tracker.snapshot(event), cfg)
        last = eng.evaluate(event, flow_ctx)

    assert sids(last) == [10, 30, 50]                     # the data packet: three detections, in rule order
    s = eng.stats
    assert s.events_evaluated == 4 and s.events_skipped == 0
    assert s.matches == 3                                  # the three handshake packets matched nothing
    assert s.candidate_rules >= 4 and s.is_consistent()


# --- detect(): match -> Detection -> record_match in one guarded block --------------------------------------------------------------------

def test_detect_returns_detections_in_rule_order():
    eng = engine(r(30, 'content:"GET";'), r(10, 'content:"../";'), r(20, 'content:"nope";'), r(5, "flags:PA;"))
    detections = eng.detect(pkt(), ctx())
    assert [d.sid for d in detections] == [30, 10, 5]
    assert all(isinstance(d, Detection) for d in detections)
    assert detections[1].matched == [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]
    assert detections[2].matched == [{"keyword": "header"}]
    assert (detections[0].flow_id, detections[0].flow_direction, detections[0].packet_id) == ("f", "to_server", 7)
    assert eng.stats.matches == 3 and eng.stats.is_consistent()


def test_detect_and_evaluate_agree_on_which_rules_match():
    lines = [r(1, 'content:"GET";'), r(2, 'content:"zzz";'), r(3, "flags:PA;"), r(4, "flow:to_client;")]
    by_detect = [d.sid for d in engine(*lines).detect(pkt(), ctx())]
    by_evaluate = sids(engine(*lines).evaluate(pkt(), ctx()))
    assert by_detect == by_evaluate == [1, 3]


def test_detect_skips_the_same_events_as_evaluate():
    eng = engine(r(1))
    assert eng.detect(pkt(processing_action="dropped"), ctx()) == []
    assert eng.stats.events_skipped == 1 and eng.stats.events_evaluated == 0


def test_a_detection_that_cannot_be_built_is_a_rule_error_and_never_a_match(monkeypatch):
    eng = engine(r(1, 'content:"GET";'), r(2, 'content:"GET";'), r(3, 'content:"GET";'))
    real = evaluator_module.make_detection

    def flaky(rule, event, ctx, matches):
        if rule.sid == 2:
            raise ValueError("cannot build")
        return real(rule, event, ctx, matches)

    monkeypatch.setattr(evaluator_module, "make_detection", flaky)
    detections = eng.detect(pkt(), ctx())
    s = eng.stats
    assert [d.sid for d in detections] == [1, 3]
    assert s.matches == len(detections) == 2                 # the numbers cannot drift from the output
    assert s.rule_errors == 1
    assert s.is_consistent()


def test_stats_matches_always_equals_the_detections_returned_over_a_run(monkeypatch):
    eng = engine(r(1, 'content:"GET";'), r(2, 'content:"GET";'))
    real = evaluator_module.make_detection
    monkeypatch.setattr(evaluator_module, "make_detection",
                        lambda rule, event, c, m: (_ for _ in ()).throw(KeyError("x")) if event.packet_id % 2 else real(rule, event, c, m))
    total = 0
    for packet_id in range(1, 7):
        total += len(eng.detect(pkt(packet_id=packet_id), ctx()))
    assert eng.stats.matches == total == 6                    # 3 even packets x 2 rules
    assert eng.stats.rule_errors == 6 and eng.stats.is_consistent()


def test_an_event_missing_packet_id_gives_rule_errors_not_a_crash():
    eng = engine(r(1, 'content:"GET";'), r(2, "flags:PA;"), r(3, 'content:"zzz";'))
    event = pkt()
    del event.packet_id
    assert eng.detect(event, ctx()) == []
    assert (eng.stats.rule_errors, eng.stats.matches) == (2, 0)      # rule 3 simply did not match
    assert eng.stats.is_consistent()


def test_evaluate_still_counts_a_match_without_building_anything(monkeypatch):
    eng = engine(r(1))
    monkeypatch.setattr(evaluator_module, "make_detection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("x")))
    assert sids(eng.evaluate(pkt(), ctx())) == [1] and eng.stats.matches == 1


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
def test_detect_does_not_swallow_base_exceptions(monkeypatch, exc):
    eng = engine(r(1))

    def stop(*a, **k):
        raise exc()

    monkeypatch.setattr(evaluator_module, "make_detection", stop)
    with pytest.raises(exc):
        eng.detect(pkt(), ctx())
