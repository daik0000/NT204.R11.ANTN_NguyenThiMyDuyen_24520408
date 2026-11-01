import pytest

from src.engine.content_matcher import content_fn
from src.engine.matcher import match_rule
from src.engine.stats import EvaluationStats
from src.models.engine_types import FlowContext
from src.models.event import IDSEvent
from src.rules.validator import parse_rule


def rule(sid, options="", header="alert tcp any any -> any 80"):
    result = parse_rule(f'{header} (msg:"r{sid}"; {options} sid:{sid};)')
    assert result.status == "valid", result
    return result.rule


def ctx(established=True, role="to_server"):
    return FlowContext(flow_id="f", protocol="TCP", state="ESTABLISHED" if established else "HANDSHAKE",
                       role=role, established=established, midstream=False, direction="forward")


def pkt(payload=b"GET /../ HTTP/1.1", flags=("PSH", "ACK"), dst_port=80):
    return IDSEvent(packet_id=1, timestamp=1.0, src_ip="10.0.0.1", src_port=40000, dst_ip="10.0.0.2", dst_port=dst_port,
                    network_protocol="IPv4", transport_protocol="TCP", raw_length=60, preprocess_status="valid",
                    payload=payload, transport_fields={"flags": list(flags)})


# --- the counters ------------------------------------------------------------------------------------------------

def test_starts_at_zero():
    assert set(EvaluationStats().to_dict().values()) == {0}


@pytest.mark.parametrize("stage, passed, field", [
    ("header", False, "rules_rejected_header"),
    ("flow", False, "rules_rejected_flow"),
    ("packet", False, "rules_rejected_packet"),
    ("content", False, "rules_rejected_content"),
])
def test_a_failed_stage_increments_only_its_own_counter(stage, passed, field):
    s = EvaluationStats()
    s.record_stage(stage, passed)
    expected = {k: 0 for k in s.to_dict()}
    expected[field] = 1
    if stage == "content":
        expected["content_evaluations"] = 1
    assert s.to_dict() == expected


@pytest.mark.parametrize("stage", ["header", "flow", "packet"])
def test_a_passed_cheap_stage_counts_nothing(stage):
    s = EvaluationStats()
    s.record_stage(stage, True)
    assert set(s.to_dict().values()) == {0}


def test_content_evaluations_counts_entering_the_stage_pass_or_fail():
    s = EvaluationStats()
    s.record_stage("content", True)
    s.record_stage("content", False)
    assert (s.content_evaluations, s.rules_rejected_content) == (2, 1)


def test_unknown_stage_is_an_error():
    with pytest.raises(ValueError):
        EvaluationStats().record_stage("payload", False)


def test_event_and_rule_counters():
    s = EvaluationStats()
    s.record_event_evaluated(4)
    s.record_event_evaluated(0)
    s.record_event_skipped()
    s.record_match()
    s.record_rule_error()
    assert (s.events_evaluated, s.candidate_rules, s.events_skipped, s.matches, s.rule_errors) == (2, 4, 1, 1, 1)
    with pytest.raises(ValueError):
        s.record_event_evaluated(-1)


def test_summary_is_one_line_with_every_counter():
    s = EvaluationStats(events_evaluated=3, events_skipped=1, candidate_rules=9, rules_rejected_header=4,
                        rules_rejected_flow=1, rules_rejected_packet=2, content_evaluations=2,
                        rules_rejected_content=1, matches=1, rule_errors=0)
    line = s.summary()
    assert "\n" not in line and line.startswith("engine: ")
    assert line == ("engine: events_evaluated=3 events_skipped=1 candidate_rules=9 rejected_header=4 "
                    "rejected_flow=1 rejected_packet=2 content_evaluations=2 rejected_content=1 "
                    "matches=1 rule_errors=0")


# --- T07: the numbers prove rules were dropped before content matching ----------------------------------------------------

def test_t07_most_rules_never_reach_content():
    rules = [
        rule(1, 'content:"../";'),                                            # passes everything -> content, match
        rule(2, 'content:"zzz";'),                                            # passes everything -> content, no match
        rule(3, 'content:"../";', header="alert tcp any any -> any 8080"),    # header
        rule(4, 'content:"../";', header="alert udp any any -> any 80"),      # header
        rule(5, 'flow:not_established; content:"../";'),                      # flow
        rule(6, 'flow:to_client; content:"../";'),                            # flow
        rule(7, 'flags:S; content:"../";'),                                   # packet
        rule(8, 'dsize:>1000; content:"../";'),                               # packet
        rule(9, 'flow:established;'),                                         # header-only match, no content
    ]
    stats, searched = EvaluationStats(), []

    def spy(r, e):
        searched.append(r.sid)
        return content_fn(r, e)

    stats.record_event_evaluated(len(rules))
    results = [match_rule(r, pkt(), ctx(), spy, stats) for r in rules]
    for result in results:
        if result.matched:
            stats.record_match()

    assert [r.matched for r in results] == [True, False, False, False, False, False, False, False, True]
    assert stats.candidate_rules == 9
    assert (stats.rules_rejected_header, stats.rules_rejected_flow, stats.rules_rejected_packet) == (2, 2, 2)
    assert stats.content_evaluations == 2 == len(searched)                  # only rules 1 and 2 got that far
    assert searched == [1, 2]
    assert stats.rules_rejected_content == 1 and stats.matches == 2
    # every candidate ends in exactly one outcome
    assert stats.candidate_rules == (stats.rules_rejected_header + stats.rules_rejected_flow
                                     + stats.rules_rejected_packet + stats.rules_rejected_content
                                     + stats.matches + stats.rule_errors)


def test_rules_rejected_early_add_nothing_to_content_evaluations():
    stats = EvaluationStats()
    for r in (rule(1, 'content:"../";', header="alert tcp any any -> any 9999"),
              rule(2, 'flags:S; content:"../";'), rule(3, 'flow:to_client; content:"../";')):
        match_rule(r, pkt(), ctx(), content_fn, stats)
    assert stats.content_evaluations == 0


def test_header_only_rule_never_adds_a_content_evaluation():
    stats = EvaluationStats()
    assert match_rule(rule(1, "flags:PA;"), pkt(), ctx(), content_fn, stats).matched is True
    assert stats.content_evaluations == 0


def test_totals_add_up_over_many_events():
    rules = [rule(1, 'content:"../";'), rule(2, 'flags:S; content:"x";'), rule(3, 'content:"nope";')]
    stats = EvaluationStats()
    events = [pkt(), pkt(b"GET / HTTP/1.1"), pkt(b"")]
    for e in events:
        stats.record_event_evaluated(len(rules))
        for r in rules:
            if match_rule(r, e, ctx(), content_fn, stats).matched:
                stats.record_match()
    assert stats.candidate_rules == 9 and stats.events_evaluated == 3
    assert stats.candidate_rules == (stats.rules_rejected_header + stats.rules_rejected_flow
                                     + stats.rules_rejected_packet + stats.rules_rejected_content
                                     + stats.matches + stats.rule_errors)
    assert stats.rules_rejected_packet == 3                  # rule 2 on every event
    assert stats.content_evaluations == 6                    # rules 1 and 3 on every event


def test_is_consistent():
    s = EvaluationStats()
    assert s.is_consistent()
    s.record_event_evaluated(3)
    assert not s.is_consistent()                       # candidates not yet accounted for
    s.record_stage("header", False)
    s.record_match()
    s.record_rule_error()
    assert s.is_consistent()


def test_a_rule_whose_content_search_raises_counts_only_as_a_rule_error():
    rules = [rule(1, 'content:"../";'), rule(2, 'content:"../";'), rule(3, 'content:"zzz";')]
    stats = EvaluationStats()

    def flaky(r, e):
        if r.sid == 2:
            raise RuntimeError("bug in rule 2")
        return content_fn(r, e)

    stats.record_event_evaluated(len(rules))
    for r in rules:                                    # what the engine will do for each candidate
        try:
            if match_rule(r, pkt(), ctx(), flaky, stats).matched:
                stats.record_match()
        except Exception:
            stats.record_rule_error()

    assert (stats.matches, stats.rule_errors, stats.rules_rejected_content) == (1, 1, 1)
    assert stats.content_evaluations == 2              # rules 1 and 3 completed; rule 2 did not
    assert stats.content_evaluations == stats.rules_rejected_content + 1      # + the matching rule that has content
    assert stats.is_consistent()
