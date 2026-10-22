import time
from types import SimpleNamespace

import pytest

from src.models.event import IDSEvent
from src.preprocessor.validator import validate

CFG = {"preprocessor": {"max_future_timestamp_skew_sec": 86400}}
TS = 1700000000.0


def make(**overrides):
    """A fully valid UDP event; tests override single fields."""
    base = dict(packet_id=1, timestamp=TS, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                network_protocol="IPv4", transport_protocol="UDP", src_port=5000, dst_port=53)
    base.update(overrides)
    return IDSEvent(**base)


def test_fully_valid_event():
    assert validate(make(), CFG) == ("valid", [])


def test_reasons_are_sorted_and_deterministic():
    status, reasons = validate(make(src_ip=None, dst_ip=None, src_port=70000), CFG)
    assert status == "invalid" and reasons == sorted(reasons)
    assert reasons == ["invalid_src_port", "missing_dst_ip", "missing_src_ip"]


@pytest.mark.parametrize("field", ["packet_id", "timestamp", "src_ip", "dst_ip", "network_protocol"])
def test_missing_required_field_is_invalid(field):
    assert validate(make(**{field: None}), CFG) == ("invalid", [f"missing_{field}"])


def test_empty_string_counts_as_missing_but_packet_id_zero_does_not():
    assert validate(make(src_ip=""), CFG) == ("invalid", ["missing_src_ip"])
    assert validate(make(packet_id=0), CFG) == ("valid", [])


def test_ports_are_required_only_for_tcp_and_udp():
    assert validate(make(src_port=None), CFG) == ("invalid", ["missing_src_port"])
    assert validate(make(transport_protocol="TCP", dst_port=None,
                         transport_fields={"flags": ["SYN"]}), CFG) == ("invalid", ["missing_dst_port"])


@pytest.mark.parametrize("port", [-1, 65536, 70000, True, "80", 80.0])
def test_invalid_port_values(port):
    assert validate(make(dst_port=port), CFG) == ("invalid", ["invalid_dst_port"])


def test_port_boundaries_and_reserved_port_zero():
    assert validate(make(src_port=1, dst_port=65535), CFG) == ("valid", [])
    assert validate(make(src_port=0), CFG) == ("partial", ["reserved_port_0"])


@pytest.mark.parametrize("ts", [float("nan"), float("inf"), float("-inf"), 0, -5.0, True, "1700000000", 10**400])
def test_invalid_timestamps_never_raise(ts):
    assert validate(make(timestamp=ts), CFG) == ("invalid", ["invalid_timestamp"])


def test_old_timestamps_are_never_rejected_because_pcap_replay_is_normal():
    assert validate(make(timestamp=1.0), CFG) == ("valid", [])
    assert validate(make(timestamp=946684800), CFG) == ("valid", [])


def test_future_timestamp_uses_the_configured_skew():
    soon = time.time() + 3600
    assert validate(make(timestamp=soon), CFG) == ("valid", [])
    tight = {"preprocessor": {"max_future_timestamp_skew_sec": 60}}
    assert validate(make(timestamp=soon), tight) == ("invalid", ["future_timestamp"])


def test_unsupported_network_protocol_is_partial_and_ipv4_is_case_insensitive():
    assert validate(make(network_protocol="IPv6"), CFG) == ("partial", ["unsupported_network:IPv6"])
    assert validate(make(network_protocol="ipv4"), CFG) == ("valid", [])


def test_arp_or_ipv6_event_from_the_parser_is_partial_not_invalid():
    # shape produced by the Bai 1 pipeline for non-IPv4 frames: status UNKNOWN, everything else None
    ev = IDSEvent(packet_id=7, timestamp=TS, status="UNKNOWN", network_fields=None, transport_fields=None)
    assert validate(ev, CFG) == ("partial", ["unsupported_network"])


def test_icmp_over_ipv4_reports_the_unsupported_transport():
    ev = make(transport_protocol=None, src_port=None, dst_port=None, network_fields={"ip_proto_number": 1})
    assert validate(ev, CFG) == ("partial", ["unsupported_transport:ICMP"])
    ev = make(transport_protocol=None, src_port=None, dst_port=None, network_fields={"ip_proto_number": 47})
    assert validate(ev, CFG) == ("partial", ["unsupported_transport:47"])


def test_ipv4_without_transport_data_is_missing_transport():
    for fields in ({"ip_proto_number": 6}, {"ip_proto_number": 17}, None):
        ev = make(transport_protocol=None, src_port=None, dst_port=None, network_fields=fields)
        assert validate(ev, CFG) == ("partial", ["missing_transport"])


def test_unsupported_transport_name_given_explicitly():
    ev = make(transport_protocol="SCTP", src_port=None, dst_port=None)
    assert validate(ev, CFG) == ("partial", ["unsupported_transport:SCTP"])


def test_malformed_event_is_invalid_with_only_the_parser_reason():
    ev = IDSEvent(packet_id=1, timestamp=TS, status="MALFORMED",
                  error_info={"layer": "parse_tcp", "detail": "too short"}, src_ip="10.0.0.1")
    assert validate(ev, CFG) == ("invalid", ["malformed_parse_tcp"])
    assert validate(IDSEvent(packet_id=1, timestamp=TS, status="MALFORMED"), CFG) == \
        ("invalid", ["malformed_unknown_layer"])


def test_tcp_flags_validation():
    tcp = dict(transport_protocol="TCP")
    assert validate(make(**tcp, transport_fields={"flags": ["SYN", "ACK"]}), CFG) == ("valid", [])
    assert validate(make(**tcp, transport_fields={"flags": []}), CFG) == ("valid", [])
    assert validate(make(**tcp, transport_fields=None), CFG) == ("valid", [])
    for bad in (["FOO"], "SYN", [1], ["SYN", None]):
        assert validate(make(**tcp, transport_fields={"flags": bad}), CFG) == ("invalid", ["invalid_tcp_flags"])


def test_degraded_decode_status_makes_the_event_partial():
    assert validate(make(decode_status="PARTIAL"), CFG) == ("partial", [])
    assert validate(make(decode_status="FAILED"), CFG) == ("partial", [])
    assert validate(make(decode_status="OK"), CFG) == ("valid", [])
    assert validate(make(decode_status="SKIPPED"), CFG) == ("valid", [])


def test_invalid_wins_over_partial():
    status, reasons = validate(make(src_port=0, dst_port=70000), CFG)
    assert status == "invalid" and set(reasons) == {"reserved_port_0", "invalid_dst_port"}


def test_object_without_any_expected_attribute_does_not_crash():
    status, reasons = validate(SimpleNamespace(), CFG)
    assert status == "invalid" and "missing_packet_id" in reasons