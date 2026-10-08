import json

import pytest

from src.models.flow import Flow


def make(**kw):
    base = dict(flow_id="abc", protocol="UDP",
                endpoint_a={"ip": "1.1.1.1", "port": 5000},
                endpoint_b={"ip": "2.2.2.2", "port": 53},
                start_time=10.0, last_seen=10.0, state="ACTIVE")
    base.update(kw)
    return Flow(**base)


def test_required_fields_cannot_be_forgotten():
    with pytest.raises(TypeError):
        Flow(flow_id="x", protocol="TCP")
    base = dict(flow_id="x", protocol="TCP", endpoint_a={}, endpoint_b={}, start_time=1.0, last_seen=1.0)
    with pytest.raises(TypeError):
        Flow(**base)  # thiếu state


def test_duration_is_derived_and_never_negative():
    f = make(start_time=10.0, last_seen=12.5)
    assert f.duration == 2.5
    f.last_seen = 15.0
    assert f.duration == 5.0
    f.last_seen = 5.0          # timestamp lệch thứ tự
    assert f.duration == 0.0


def test_to_dict_includes_duration_next_to_last_seen_and_is_json_serializable():
    d = make(last_seen=11.0).to_dict()
    keys = list(d)
    assert keys.index("duration") == keys.index("last_seen") + 1
    assert d["duration"] == 1.0
    json.dumps(d)


def test_udp_defaults_tcp_counters_zero():
    d = make().to_dict()
    assert (d["syn_count"], d["ack_count"], d["fin_count"], d["rst_count"]) == (0, 0, 0, 0)
    assert d["state"] == "ACTIVE" and d["close_reason"] is None and d["midstream"] is False


def test_covers_assignment_table_5_4():
    need = {"flow_id", "protocol", "application_protocol", "endpoint_a", "endpoint_b",
            "start_time", "last_seen", "duration", "packet_count", "byte_count",
            "fwd_packet_count", "fwd_byte_count", "bwd_packet_count", "bwd_byte_count",
            "syn_count", "ack_count", "fin_count", "rst_count", "state"}
    assert need <= set(make().to_dict())