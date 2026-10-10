import time

from src.models.event import IDSEvent
from src.preprocessor.preprocessor import preprocess_event


def cfg(unsupported="mark", invalid="flag"):
    return {"preprocessor": {"max_future_timestamp_skew_sec": 60,
                             "unsupported_policy": unsupported,
                             "invalid_policy": invalid}}


def tcp(**kw):
    d = dict(packet_id=1, timestamp=time.time() - 5, src_ip="10.0.0.1", dst_ip="10.0.0.2",
             network_protocol="IPv4", network_fields={"ip_proto_number": 6},
             src_port=1234, dst_port=80, transport_protocol="TCP",
             transport_fields={"flags": ["SYN"]})
    d.update(kw)
    return IDSEvent(**d)


def test_clean_tcp_event_is_valid_and_untouched():
    ev = preprocess_event(tcp(), cfg())
    assert (ev.preprocess_status, ev.processing_action) == ("valid", "none")
    assert ev.reason == []


def test_protocol_alias_is_normalized():
    ev = preprocess_event(tcp(network_protocol="ip"), cfg())
    assert ev.network_protocol == "IPv4" and ev.processing_action == "normalized"


def test_invalid_event_skips_normalization_and_follows_invalid_policy():
    out = preprocess_event(tcp(src_port=70000, network_protocol="ip"), cfg())
    assert out.network_protocol == "ip"                       # normalizer was skipped
    assert (out.preprocess_status, out.processing_action) == ("invalid", "flagged")
    assert "invalid_src_port" in out.reason
    assert preprocess_event(tcp(src_port=70000), cfg(invalid="drop")).processing_action == "dropped"


def test_icmp_and_unknown_follow_unsupported_policy():
    icmp = IDSEvent(1, time.time() - 5, src_ip="1.1.1.1", dst_ip="2.2.2.2",
                    network_protocol="IPv4", network_fields={"ip_proto_number": 1})
    preprocess_event(icmp, cfg())
    assert (icmp.preprocess_status, icmp.processing_action) == ("partial", "flagged")
    arp = preprocess_event(IDSEvent(2, 1.0, status="UNKNOWN"), cfg("skip"))
    assert arp.processing_action == "skipped"


def test_malformed_event_gets_single_clear_reason():
    ev = IDSEvent(3, 1.0, status="MALFORMED", error_info={"layer": "parse_tcp", "detail": "x"})
    out = preprocess_event(ev, cfg())
    assert out.reason == ["malformed_parse_tcp"] and out.processing_action == "flagged"


def test_second_call_keeps_status_and_does_not_duplicate_reasons():
    ev = preprocess_event(tcp(network_protocol="ip", src_port=0), cfg())
    status, reasons = ev.preprocess_status, list(ev.reason)
    preprocess_event(ev, cfg())
    assert ev.preprocess_status == status and ev.reason == reasons


def test_none_reason_and_none_containers_are_repaired():
    ev = preprocess_event(tcp(reason=None, app_fields=None, decoded_fields=None), cfg())
    assert ev.reason == [] and ev.app_fields == {} and ev.processing_action == "defaults_filled"


def test_decode_partial_is_partial_but_not_flagged():
    ev = preprocess_event(tcp(decode_status="PARTIAL"), cfg())
    assert (ev.preprocess_status, ev.processing_action) == ("partial", "none")


def test_stage_crash_leaves_fail_safe_verdict():
    ev = preprocess_event(tcp(), {})            # cfg without "preprocessor" -> KeyError inside the stage
    assert ev.error_info["layer"] == "preprocessor"
    assert (ev.preprocess_status, ev.processing_action) == ("invalid", "flagged")