import pytest

from src.models.event import IDSEvent
from src.pipeline import pipeline as pl
from src.pipeline.pipeline import Pipeline, process_packet


@pytest.fixture(autouse=True)
def fake_parsers(monkeypatch):
    def ipv4(raw):
        if raw.startswith(b"M"):
            return {"status": "MALFORMED", "error_info": {"layer": "parse_ipv4", "detail": "truncated"}}
        return {"status": "OK", "network_protocol": "IPv4", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "network_fields": {"ip_proto_number": 17}, "transport_payload": raw[1:]}

    monkeypatch.setattr(pl, "parse_ipv4", ipv4)
    monkeypatch.setattr(pl, "parse_udp", lambda p: {"status": "OK", "transport_protocol": "UDP", "src_port": 1000,
                                                    "dst_port": 53, "transport_fields": {}, "app_payload": p})
    monkeypatch.setattr(pl, "detect_application_protocol", lambda **kw: ("UNKNOWN", "none"))


def spy(monkeypatch, calls, decoder=None, preprocessor=None):
    def dec(event, cfg):
        calls.append("decoder")
        return decoder(event, cfg) if decoder else event

    def pre(event, cfg):
        calls.append("preprocessor")
        if preprocessor:
            return preprocessor(event, cfg)
        event.preprocess_status = "valid"
        event.processing_action = "none"
        return event

    monkeypatch.setattr(pl, "decode_event", dec)
    monkeypatch.setattr(pl, "preprocess_event", pre)


def boom(event, cfg):
    raise RuntimeError("kaboom")


def test_stage_order_is_parser_decoder_preprocessor(monkeypatch):
    calls = []
    spy(monkeypatch, calls)
    ev = Pipeline({}).process(1.0, b"Xhello", 1)
    assert calls == ["decoder", "preprocessor"] and ev.preprocess_status == "valid"


def test_malformed_event_skips_decoder_but_still_reaches_preprocessor(monkeypatch):
    calls = []
    spy(monkeypatch, calls)
    ev = Pipeline({}).process(1.0, b"Mxxxx", 1)
    assert calls == ["preprocessor"]
    assert ev.status == "MALFORMED" and ev.decode_status is None
    assert ev.error_info == {"layer": "parse_ipv4", "detail": "truncated"}


def test_decoder_crash_does_not_block_preprocessor_and_is_recorded_as_dict(monkeypatch):
    calls = []
    spy(monkeypatch, calls, decoder=boom)
    ev = Pipeline({}).process(1.0, b"Xhello", 1)
    assert calls == ["decoder", "preprocessor"] and ev.decode_status is None
    assert ev.error_info["layer"] == "decoder" and "kaboom" in ev.error_info["detail"]


def test_decoder_crash_keeps_an_earlier_error_info(monkeypatch):
    def fail_after_marking(e, c):
        e.error_info = {"layer": "x", "detail": "first"}
        boom(e, c)

    calls = []
    spy(monkeypatch, calls, decoder=fail_after_marking)
    ev = Pipeline({}).process(1.0, b"Xhello", 1)
    assert ev.error_info == {"layer": "x", "detail": "first"}


def test_preprocessor_crash_falls_back_to_invalid_flagged(monkeypatch):
    calls = []
    spy(monkeypatch, calls, preprocessor=boom)
    ev = Pipeline({}).process(1.0, b"Xhello", 1)
    assert (ev.preprocess_status, ev.processing_action) == ("invalid", "flagged")
    assert ev.error_info["layer"] == "preprocessor" and "kaboom" in ev.error_info["detail"]
    assert "preprocessor_error" in ev.reason


def test_preprocessor_returning_no_verdict_falls_back(monkeypatch):
    calls = []
    spy(monkeypatch, calls, preprocessor=lambda e, c: e)   # leaves preprocess_status None
    ev = Pipeline({}).process(1.0, b"Xhello", 1)
    assert (ev.preprocess_status, ev.processing_action) == ("invalid", "flagged")


def test_stage_returning_a_non_event_keeps_the_previous_event(monkeypatch):
    calls = []
    spy(monkeypatch, calls, decoder=lambda e, c: None)
    ev = Pipeline({}).process(1.0, b"Xhello", 1)
    assert isinstance(ev, IDSEvent) and ev.preprocess_status == "valid"


def test_parser_exception_becomes_malformed_event_and_still_gets_a_verdict(monkeypatch):
    calls = []
    spy(monkeypatch, calls)

    def bad_parser(raw):
        raise RuntimeError("bad parser")

    monkeypatch.setattr(pl, "parse_ipv4", bad_parser)
    ev = Pipeline({}).process(5.0, b"Xhello", 9)
    assert ev.status == "MALFORMED" and ev.packet_id == 9 and ev.timestamp == 5.0 and ev.raw_length == 6
    assert ev.error_info["layer"] == "parser" and "bad parser" in ev.error_info["detail"]
    assert calls == ["preprocessor"]


@pytest.mark.parametrize("raw", [None, "text", 123, b"", bytearray(b"Xab"), memoryview(b"Xab")])
def test_process_never_raises_and_error_info_is_always_a_dict_or_none(monkeypatch, raw):
    spy(monkeypatch, [])
    ev = Pipeline({}).process(1.0, raw, 1)
    assert isinstance(ev, IDSEvent)
    assert ev.error_info is None or isinstance(ev.error_info, dict)


def test_non_bytes_input_is_reported_as_parser_error(monkeypatch):
    spy(monkeypatch, [])
    ev = Pipeline({}).process(1.0, None, 1)
    assert ev.status == "MALFORMED" and ev.error_info["layer"] == "parser" and ev.raw_length == 0


def test_part1_wrapper_does_not_run_part2_stages(monkeypatch):
    calls = []
    spy(monkeypatch, calls)
    ev = process_packet(1.0, b"Xhello", 1)
    assert calls == [] and ev.preprocess_status is None and ev.decode_status is None

def test_real_decoder_and_preprocessor_give_every_event_a_verdict():
    for raw in (b"Xhello", b"Mxxxx", b"X"):
        ev = Pipeline({}).process(1.0, raw, 1)
        assert ev.preprocess_status in ("valid", "partial", "invalid")