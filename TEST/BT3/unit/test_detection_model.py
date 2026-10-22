import json

import pytest

from src.models.detection import Detection


def _det(**kw):
    base = dict(sid=1000001, rev=1, msg="m", priority=2, timestamp=1.5, packet_id=7,
                src_ip="10.0.0.1", src_port=1234, dst_ip="10.0.0.2", dst_port=80, protocol="TCP")
    base.update(kw)
    return Detection(**base)


def test_defaults_and_header_fallback():
    d = _det()
    assert d.classtype is None and d.application_protocol is None
    assert d.flow_id is None and d.flow_direction is None
    assert d.matched == [{"keyword": "header"}]


@pytest.mark.parametrize("empty", [[], None])
def test_empty_matched_becomes_header(empty):
    assert _det(matched=empty).matched == [{"keyword": "header"}]


def test_content_match_kept():
    m = [{"keyword": "content", "value": "../", "offset": 5, "length": 3}]
    assert _det(matched=m).matched == m


def test_matched_default_not_shared():
    a, b = _det(), _det()
    a.matched.append({"keyword": "content"})
    assert b.matched == [{"keyword": "header"}]


def test_constructor_copies_matched():
    m = [{"keyword": "content", "value": "x", "offset": 0, "length": 1}]
    a, b = _det(matched=m), _det(matched=m)
    m[0]["offset"] = 99
    m.append({"keyword": "header"})
    assert a.matched == b.matched == [{"keyword": "content", "value": "x", "offset": 0, "length": 1}]
    assert a.matched is not b.matched and a.matched[0] is not b.matched[0]


def test_to_dict_is_json_serialisable_and_complete():
    d = _det(flow_id="f1", flow_direction="to_server", application_protocol="HTTP",
             matched=[{"keyword": "content", "value": "../", "offset": 5, "length": 3}]).to_dict()
    assert list(d) == [
        "sid", "rev", "msg", "priority", "classtype", "timestamp", "packet_id",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "application_protocol", "flow_id", "flow_direction", "matched",
    ]
    assert json.loads(json.dumps(d)) == d


def test_to_dict_does_not_alias():
    det = _det()
    det.to_dict()["matched"].append({"keyword": "x"})
    assert det.matched == [{"keyword": "header"}]


@pytest.mark.parametrize("kw", [
    dict(protocol="ICMP"), dict(protocol="tcp"), dict(flow_direction="forward"),
    dict(matched=[{"keyword": "pcre"}]),
    dict(matched=[{"keyword": "content"}]),
    dict(matched=[{"keyword": "content", "value": "x", "offset": -1, "length": 1}]),
    dict(matched=[{"keyword": "content", "value": "x", "offset": 0, "length": 0}]),
    dict(matched=[{"keyword": "content", "value": b"x", "offset": 0, "length": 1}]),
    dict(matched=[{"keyword": "content", "value": "x", "offset": True, "length": 1}]), dict(matched=["content"]), dict(matched=[{"value": "x"}]),
])
def test_invalid_values(kw):
    with pytest.raises(ValueError):
        _det(**kw)


def test_requires_keyword_arguments():
    with pytest.raises(TypeError):
        Detection(1, 1, "m", 1, None, 0.0, 1, "a", 1, "b", 2, "TCP")
