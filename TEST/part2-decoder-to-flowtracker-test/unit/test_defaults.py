import pytest
from src.models.event import IDSEvent
from src.preprocessor.defaults import fill_defaults, apply_policies


def cfg(unsupported="mark", invalid="flag"):
    return {"preprocessor": {"unsupported_policy": unsupported, "invalid_policy": invalid}}


# ---------- fill_defaults ----------

def test_none_containers_become_empty_dicts_and_second_call_changes_nothing():
    ev = IDSEvent(1, 1.0, network_fields=None, transport_fields=None, app_fields=None, decoded_fields=None)
    assert fill_defaults(ev) is True
    assert ev.network_fields == {} and ev.transport_fields == {} and ev.app_fields == {} and ev.decoded_fields == {}
    assert fill_defaults(ev) is False  # idempotent


def test_complete_event_is_left_alone():
    ev = IDSEvent(1, 1.0, transport_protocol="UDP", transport_fields={"length": 12})
    assert fill_defaults(ev) is False and ev.transport_fields == {"length": 12}


def test_flags_default_only_for_tcp():
    tcp = IDSEvent(1, 1.0, transport_protocol="tcp", transport_fields={})
    assert fill_defaults(tcp) is True and tcp.transport_fields == {"flags": []}
    for proto in ("UDP", "ICMP", None):
        other = IDSEvent(1, 1.0, transport_protocol=proto, transport_fields=None)
        fill_defaults(other)
        assert "flags" not in other.transport_fields, proto


def test_tcp_flags_none_becomes_list_and_real_flags_kept():
    a = IDSEvent(1, 1.0, transport_protocol="TCP", transport_fields={"flags": None})
    fill_defaults(a)
    assert a.transport_fields["flags"] == []
    b = IDSEvent(1, 1.0, transport_protocol="TCP", transport_fields={"flags": ["SYN"]})
    assert fill_defaults(b) is False and b.transport_fields["flags"] == ["SYN"]


def test_http_dns_collections():
    http = IDSEvent(1, 1.0, app_protocol="HTTP", app_fields={"headers": {"Host": "a"}})
    assert fill_defaults(http) is True
    assert http.app_fields == {"headers": {"Host": "a"}, "header_pairs": []}
    dns = IDSEvent(1, 1.0, app_protocol="DNS", app_fields={})
    fill_defaults(dns)
    assert dns.app_fields == {"queries": [], "answers": []}
    smtp = IDSEvent(1, 1.0, app_protocol="SMTP", app_fields={})
    assert fill_defaults(smtp) is False and smtp.app_fields == {}


def test_reason_none_and_non_dict_containers_repaired():
    ev = IDSEvent(1, 1.0, reason=None, transport_fields=["junk"], app_fields="junk")
    assert fill_defaults(ev) is True
    assert ev.reason == [] and ev.transport_fields == {} and ev.app_fields == {}


def test_pipeline_shaped_events():
    udp = IDSEvent(1, 1.0, transport_protocol="UDP", transport_fields={"length": 12}, app_fields=None)
    fill_defaults(udp)
    assert udp.transport_fields == {"length": 12} and udp.app_fields == {}
    arp = IDSEvent(2, 1.0, status="UNKNOWN", network_fields=None, transport_fields=None, app_fields=None)
    fill_defaults(arp)
    assert arp.transport_fields == {}


# ---------- apply_policies ----------

def run(status, reasons=(), c=None, norm=False, defaults=False):
    ev = IDSEvent(1, 1.0)
    apply_policies(ev, status, list(reasons), c or cfg(), norm, defaults)
    return ev.preprocess_status, ev.processing_action


def test_benign_actions():
    assert run("valid") == ("valid", "none")
    assert run("valid", defaults=True) == ("valid", "defaults_filled")
    assert run("valid", norm=True) == ("valid", "normalized")
    assert run("valid", norm=True, defaults=True) == ("valid", "normalized")


def test_invalid_policy():
    assert run("invalid", ["x"], cfg(invalid="flag")) == ("invalid", "flagged")
    assert run("invalid", ["x"], cfg(invalid="drop")) == ("invalid", "dropped")


@pytest.mark.parametrize("reason", ["unsupported_network", "unsupported_network:IPv6", "unsupported_transport:ICMP"])
def test_unsupported_policy(reason):
    assert run("partial", [reason], cfg(unsupported="mark")) == ("partial", "flagged")
    assert run("partial", [reason], cfg(unsupported="skip")) == ("partial", "skipped")
    assert run("valid", [reason]) == ("partial", "flagged")  # forced to partial


def test_precedence():
    assert run("partial", ["unsupported_transport:ICMP"], norm=True, defaults=True) == ("partial", "flagged")
    assert run("invalid", ["unsupported_network", "invalid_src_port"], cfg(invalid="drop")) == ("invalid", "dropped")


def test_other_partial_reasons_not_flagged():
    assert run("partial", ["reserved_port_0"], cfg(unsupported="skip")) == ("partial", "none")
    assert run("partial", ["missing_transport"], cfg(unsupported="skip"), norm=True) == ("partial", "normalized")


def test_bai1_unknown_policy_has_no_effect():
    c = cfg()
    c["unknown_policy"] = "skip"
    ev = IDSEvent(1, 1.0, status="IGNORED")
    apply_policies(ev, "valid", [], c, False, False)
    assert (ev.preprocess_status, ev.processing_action) == ("valid", "none")