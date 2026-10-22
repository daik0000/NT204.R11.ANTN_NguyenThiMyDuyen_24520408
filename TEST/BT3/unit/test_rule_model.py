import dataclasses

import pytest

from src.models.rule import (
    ContentSpec, DsizeSpec, FlagsSpec, FlowSpec, IpSpec, PortSpec, Rule,
)


def _rule(**kw):
    base = dict(
        action="alert", protocol="tcp",
        src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535),
        direction="->",
        dst_ip=IpSpec(any=False, network=0xC0A80100, mask=0xFFFFFF00), dst_port=PortSpec(80, 80),
        msg="m", sid=1,
    )
    base.update(kw)
    return Rule(**base)


def test_rule_defaults():
    r = _rule()
    assert (r.rev, r.classtype, r.priority) == (1, None, None)
    assert r.contents == () and r.flow is None and r.flags is None and r.dsize is None
    assert (r.source_file, r.line_no, r.raw) == ("", 0, "")


def test_rule_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _rule().sid = 2
    with pytest.raises(dataclasses.FrozenInstanceError):
        _rule().dst_port.lo = 1


def test_rule_is_hashable_and_comparable():
    assert _rule() == _rule()
    assert hash(_rule(contents=(ContentSpec("a", b"a"),))) == hash(_rule(contents=(ContentSpec("a", b"a"),)))


def test_port_is_any():
    assert PortSpec(0, 65535).is_any
    assert not PortSpec(80, 80).is_any
    assert not PortSpec(0, 1023).is_any


@pytest.mark.parametrize("lo, hi", [(-1, 5), (10, 5), (0, 65536)])
def test_port_invalid(lo, hi):
    with pytest.raises(ValueError):
        PortSpec(lo, hi)


def test_ip_range_check():
    with pytest.raises(ValueError):
        IpSpec(any=False, network=2**32, mask=0)
    with pytest.raises(ValueError):
        IpSpec(any=False, network=0, mask=-1)


def test_cidr_semantics():
    spec = IpSpec(any=False, network=0xC0A80100, mask=0xFFFFFF00)
    assert (0xC0A80105 & spec.mask) == spec.network


def test_content_requires_pattern():
    with pytest.raises(ValueError):
        ContentSpec(raw="", pattern=b"")
    c = ContentSpec(raw="../", pattern=b"../")
    assert (c.nocase, c.offset, c.depth, c.distance, c.within) == (False, None, None, None, None)


@pytest.mark.parametrize("role, state", [("server", None), (None, "open")])
def test_flow_spec_invalid(role, state):
    with pytest.raises(ValueError):
        FlowSpec(role=role, state=state)


def test_flow_spec_valid():
    assert FlowSpec("to_server", "established").state == "established"
    assert FlowSpec().role is None


def test_flags_spec():
    assert FlagsSpec("exact", frozenset({"S"})).mode == "exact"
    with pytest.raises(ValueError):
        FlagsSpec("some", frozenset({"S"}))
    with pytest.raises(ValueError):
        FlagsSpec("exact", frozenset({"X"}))


def test_dsize_spec():
    assert DsizeSpec("range", 1, 10).b == 10
    assert DsizeSpec("gt", 5).b is None
    for bad in (lambda: DsizeSpec("ne", 1), lambda: DsizeSpec("range", 5),
                lambda: DsizeSpec("range", 5, 1), lambda: DsizeSpec("eq", 1, 2),
                lambda: DsizeSpec("eq", -1)):
        with pytest.raises(ValueError):
            bad()


@pytest.mark.parametrize("field, value", [
    ("action", "drop"), ("protocol", "icmp"), ("direction", "<-"), ("priority", 0),
])
def test_rule_invalid_enums(field, value):
    with pytest.raises(ValueError):
        _rule(**{field: value})
