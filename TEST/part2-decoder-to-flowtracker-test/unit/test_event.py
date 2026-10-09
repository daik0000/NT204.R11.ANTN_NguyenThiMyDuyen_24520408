import json

from src.models.event import IDSEvent


def test_bai1_style_construction_still_works():
    e = IDSEvent(packet_id=1, timestamp=1.0, src_ip="1.1.1.1", status="OK")
    assert e.decode_status is None and e.preprocess_status is None
    assert e.reason == [] and e.decoded_fields == {} and e.flow_id is None


def test_mutable_defaults_not_shared():
    a, b = IDSEvent(1, 1.0), IDSEvent(2, 2.0)
    a.reason.append("x")
    a.decoded_fields["k"] = 1
    a.app_fields["z"] = 1
    assert b.reason == [] and b.decoded_fields == {} and b.app_fields == {}


def test_to_dict_excludes_payload_and_is_json_serializable():
    d = IDSEvent(1, 1.0, payload=b"\xff\xfe raw").to_dict()
    assert "payload" not in d
    json.dumps(d, ensure_ascii=False)


def test_app_protocol_none_means_detector_not_run():
    assert IDSEvent(1, 1.0).app_protocol is None