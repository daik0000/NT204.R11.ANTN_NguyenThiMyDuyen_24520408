import pytest

from src.engine.matcher import STAGES, match_rule
from src.models.engine_types import FAILED_STAGES, FlowContext
from src.models.event import IDSEvent
from src.rules.validator import parse_rule


def rule(options, header="alert tcp any any -> any 80"):
    result = parse_rule(f'{header} (msg:"x"; {options} sid:1;)')
    assert result.status == "valid", result
    return result.rule


def pkt(flags=("ACK",), payload=b"", src=("10.0.0.1", 40000), dst=("10.0.0.2", 80), proto="TCP"):
    return IDSEvent(packet_id=1, timestamp=1.0, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
                    network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
                    payload=payload, transport_fields={"flags": list(flags)} if proto == "TCP" else {})


def ctx(role="to_server", established=True):
    return FlowContext(flow_id="f", protocol="TCP", state="ESTABLISHED" if established else "HANDSHAKE",
                       role=role, established=established, midstream=False, direction="forward")


class Stats:
    def __init__(self):
        self.calls = []

    def record_stage(self, stage, passed):
        self.calls.append((stage, passed))


class ContentSpy:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def __call__(self, rule, event):
        self.calls += 1
        return self.result


FOUND = [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]


# --- which stage fails ------------------------------------------------------------------------------------------------

def test_stage_names_are_shared_with_match_result():
    assert STAGES == ("header", "flow", "packet", "content")
    assert STAGES is FAILED_STAGES


def test_header_fails_first():
    r = match_rule(rule("flow:established; flags:S; dsize:>100;"), pkt(dst=("10.0.0.2", 8080)), ctx(established=False))
    assert (r.matched, r.failed_stage, r.matches) == (False, "header", [])


def test_flow_fails_after_header_passes():
    r = match_rule(rule("flow:established; flags:S; dsize:>100;"), pkt(), ctx(established=False))
    assert (r.matched, r.failed_stage) == (False, "flow")


def test_flow_fails_when_there_is_no_context():
    assert match_rule(rule("flow:to_server;"), pkt(), None).failed_stage == "flow"


def test_rule_without_flow_option_ignores_a_missing_context():
    assert match_rule(rule(""), pkt(), None).matched is True


@pytest.mark.parametrize("options", ["flags:S;", "dsize:>100;", "flags:A; dsize:>100;", "flags:S; dsize:0;"])
def test_packet_stage_fails_on_flags_or_dsize(options):
    r = match_rule(rule(f"flow:established; {options}"), pkt(["ACK"], b""), ctx())
    assert (r.matched, r.failed_stage) == (False, "packet")


def test_packet_stage_needs_both_flags_and_dsize():
    r = rule("flags:PA; dsize:3;")
    assert match_rule(r, pkt(["PSH", "ACK"], b"abc"), ctx()).matched is True
    assert match_rule(r, pkt(["PSH", "ACK"], b"abcd"), ctx()).failed_stage == "packet"
    assert match_rule(r, pkt(["ACK"], b"abc"), ctx()).failed_stage == "packet"


def test_content_stage_fails():
    spy = ContentSpy(None)
    r = match_rule(rule('content:"../";'), pkt(payload=b"GET /"), ctx(), spy)
    assert (r.matched, r.failed_stage, r.matches) == (False, "content", [])
    assert spy.calls == 1


@pytest.mark.parametrize("empty", [None, []])
def test_content_fn_returning_nothing_means_content_failed(empty):
    assert match_rule(rule('content:"a";'), pkt(), ctx(), ContentSpy(empty)).failed_stage == "content"


def test_rule_with_content_but_no_content_fn_cannot_be_confirmed():
    r = match_rule(rule('content:"a";'), pkt(), ctx())
    assert (r.matched, r.failed_stage) == (False, "content")


# --- success ----------------------------------------------------------------------------------------------------------------------

def test_header_only_rule_matches_with_header_marker_and_never_calls_content_fn():
    spy = ContentSpy(FOUND)
    r = match_rule(rule("flow:established;"), pkt(), ctx(), spy)
    assert (r.matched, r.failed_stage, r.matches) == (True, None, [{"keyword": "header"}])
    assert spy.calls == 0


def test_content_rule_matches_with_the_details_from_content_fn():
    spy = ContentSpy(FOUND)
    r = match_rule(rule('content:"../";'), pkt(payload=b"GET ../"), ctx(), spy)
    assert (r.matched, r.failed_stage, r.matches) == (True, None, FOUND)
    assert spy.calls == 1 and r.rule.sid == 1


def test_matches_is_a_copy_of_what_content_fn_returned():
    found = list(FOUND)
    r = match_rule(rule('content:"../";'), pkt(), ctx(), ContentSpy(found))
    found.clear()
    assert r.matches == FOUND


def test_content_fn_receives_the_rule_and_the_event():
    seen = []
    rl, ev = rule('content:"a";'), pkt()
    match_rule(rl, ev, ctx(), lambda r, e: seen.append((r, e)) or FOUND)
    assert seen == [(rl, ev)]


# --- order is cheap -> expensive, and nothing later runs after a failure ----------------------------------------------------------------------

@pytest.mark.parametrize("event, context, expected", [
    (pkt(dst=("10.0.0.2", 8080)), ctx(), [("header", False)]),
    (pkt(), ctx(established=False), [("header", True), ("flow", False)]),
    (pkt(["ACK"], b""), ctx(), [("header", True), ("flow", True), ("packet", False)]),
    (pkt(["SYN"], b""), ctx(), [("header", True), ("flow", True), ("packet", True), ("content", False)]),
])
def test_stages_are_evaluated_in_order_and_stop_at_the_first_failure(event, context, expected):
    stats, spy = Stats(), ContentSpy(None)
    rl = rule('flow:established; flags:S; dsize:0; content:"a";')
    r = match_rule(rl, event, context, spy, stats)
    assert stats.calls == expected
    assert r.failed_stage == expected[-1][0]
    assert spy.calls == (1 if len(expected) == 4 else 0)       # content_fn only after every cheap stage passed


def test_full_success_records_every_stage():
    stats = Stats()
    match_rule(rule('flow:established; flags:A; dsize:0; content:"a";'), pkt(), ctx(), ContentSpy(FOUND), stats)
    assert stats.calls == [("header", True), ("flow", True), ("packet", True), ("content", True)]


def test_header_only_rule_never_records_a_content_stage():
    stats = Stats()
    match_rule(rule(""), pkt(), ctx(), None, stats)
    assert [s for s, _ in stats.calls] == ["header", "flow", "packet"]


def test_stats_is_optional():
    assert match_rule(rule(""), pkt(), ctx()).matched is True
    assert match_rule(rule(""), pkt(), ctx(), None, None).matched is True


def test_content_is_never_reached_by_a_rule_that_fails_earlier_even_if_content_fn_would_raise():
    def boom(rule, event):
        raise AssertionError("content stage must not run")
    assert match_rule(rule('flags:S; content:"a";'), pkt(["ACK"]), ctx(), boom).failed_stage == "packet"


def test_content_fn_exception_is_not_swallowed():
    def boom(rule, event):
        raise RuntimeError("bug")
    with pytest.raises(RuntimeError):
        match_rule(rule('content:"a";'), pkt(), ctx(), boom)


# --- unidirectional / bidirectional header through the orchestrator --------------------------------------------------------------------------------

def test_bidirectional_rule_matches_the_reverse_packet_end_to_end():
    both = rule("flow:to_client;", header="alert tcp any any <> any 80")
    reverse = pkt(src=("10.0.0.2", 80), dst=("10.0.0.1", 40000))
    assert match_rule(both, reverse, ctx(role="to_client")).matched is True
    one_way = rule("flow:to_client;", header="alert tcp any any -> any 80")
    assert match_rule(one_way, reverse, ctx(role="to_client")).failed_stage == "header"


def test_matches_dicts_are_copied_too():
    found = [dict(FOUND[0])]
    r = match_rule(rule('content:"../";'), pkt(), ctx(), ContentSpy(found))
    found[0]["offset"] = 999
    assert r.matches[0]["offset"] == 5


@pytest.mark.parametrize("options, event, context, content_fn", [
    ("", pkt(), ctx(), None),                                              # match, header only
    ('content:"a";', pkt(), ctx(), ContentSpy(FOUND)),                     # match with content
    ("", pkt(dst=("1.1.1.1", 1)), ctx(), None),                            # header
    ("flow:to_client;", pkt(), ctx(), None),                               # flow
    ("flags:S;", pkt(), ctx(), None),                                      # packet
    ('content:"a";', pkt(), ctx(), ContentSpy(None)),                      # content
])
def test_result_always_obeys_the_match_result_contract(options, event, context, content_fn):
    r = match_rule(rule(options), event, context, content_fn)
    if r.matched:
        assert r.failed_stage is None and len(r.matches) >= 1
    else:
        assert r.failed_stage in STAGES and r.matches == []
