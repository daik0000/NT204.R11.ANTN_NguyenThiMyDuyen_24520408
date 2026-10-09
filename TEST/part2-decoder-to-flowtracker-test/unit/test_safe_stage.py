import pytest

from src.models.event import IDSEvent
from src.utils.safe import safe_parse, safe_stage


@safe_stage("decoder")
def ok_stage(event):
    event.decode_status = "OK"
    return event


@safe_stage("decoder")
def crashing_stage(event):
    event.decode_status = "PARTIAL"      # partial change made before the crash
    raise ValueError("boom")


def test_success_returns_the_stage_result_and_keeps_function_name():
    ev = IDSEvent(1, 1.0)
    assert ok_stage(ev) is ev and ev.decode_status == "OK"
    assert ok_stage.__name__ == "ok_stage"


def test_crash_returns_the_same_event_and_records_error_info():
    ev = IDSEvent(1, 1.0)
    out = crashing_stage(ev)
    assert out is ev
    assert ev.error_info == {"layer": "decoder", "detail": "boom"}
    assert ev.decode_status == "PARTIAL"       # partial modification is kept


def test_prior_parser_error_is_not_overwritten():
    prior = {"layer": "parse_tcp", "detail": "too short"}
    ev = IDSEvent(1, 1.0, status="MALFORMED", error_info=dict(prior))
    assert crashing_stage(ev).error_info == prior


def test_event_can_be_passed_as_keyword():
    ev = IDSEvent(1, 1.0)
    assert crashing_stage(event=ev) is ev and ev.error_info["layer"] == "decoder"


def test_works_on_methods_with_event_index_1():
    class Tracker:
        @safe_stage("flow_tracker", event_index=1)
        def update(self, event):
            raise RuntimeError("x")

    ev = IDSEvent(1, 1.0)
    assert Tracker().update(ev) is ev
    assert ev.error_info == {"layer": "flow_tracker", "detail": "x"}


def test_error_handler_never_raises_when_event_is_not_writable():
    assert crashing_stage(None) is None
    assert crashing_stage(42) == 42


def test_keyboard_interrupt_is_not_swallowed():
    @safe_stage("decoder")
    def interrupted(event):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        interrupted(IDSEvent(1, 1.0))


def test_safe_parse_behaviour_is_unchanged():
    @safe_parse
    def parse_x(raw):
        raise ValueError("bad")

    assert parse_x(b"") == {"status": "MALFORMED",
                            "error_info": {"layer": "parse_x", "detail": "bad"}}