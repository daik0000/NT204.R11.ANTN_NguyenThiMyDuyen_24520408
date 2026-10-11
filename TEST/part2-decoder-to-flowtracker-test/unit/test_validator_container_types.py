from src.models.event import IDSEvent
from src.preprocessor.validator import validate

CFG = {"preprocessor": {"max_future_timestamp_skew_sec": 86400}}


def _event(**overrides):
    base = dict(packet_id=1, timestamp=1700000000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", network_protocol="IPv4")
    base.update(overrides)
    return IDSEvent(**base)


def test_non_dict_transport_fields_does_not_raise():
    event = _event(transport_protocol="TCP", src_port=1000, dst_port=80, transport_fields="x")
    assert validate(event, CFG) == ("valid", [])


def test_non_dict_network_fields_does_not_raise():
    event = _event(network_fields=["x"])                       # no transport layer -> the code reads network_fields
    assert validate(event, CFG) == ("partial", ["missing_transport"])


def test_dict_containers_still_work():
    event = _event(network_fields={"ip_proto_number": 1})
    assert validate(event, CFG) == ("partial", ["unsupported_transport:ICMP"])