import dataclasses

import pytest

from src.models.engine_types import FAILED_STAGES, FlowContext, MatchResult
from src.models.rule import IpSpec, PortSpec, Rule

RULE = Rule(action="alert", protocol="tcp", src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535),
            direction="->", dst_ip=IpSpec(any=True), dst_port=PortSpec(0, 65535), msg="m", sid=1)


def _ctx(**kw):
    base = dict(flow_id="f1", protocol="TCP", state="ESTABLISHED", role="to_server",
                established=True, midstream=False, direction="forward")
    base.update(kw)
    return FlowContext(**base)


def test_flow_context_valid_and_frozen():
    c = _ctx()
    assert c.role == "to_server" and c.established is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.role = "to_client"


def test_flow_context_udp_active():
    assert _ctx(protocol="UDP", state="ACTIVE", established=False).state == "ACTIVE"


def test_flow_context_role_may_be_none():
    assert _ctx(role=None).role is None


@pytest.mark.parametrize("kw", [
    dict(protocol="ICMP"), dict(state="OPEN"), dict(state="ACTIVE"),
    dict(protocol="UDP"), dict(protocol="UDP", state="HANDSHAKE"), dict(role="server"), dict(direction="a_to_b"),
    dict(established=1), dict(midstream=None),
])
def test_flow_context_invalid(kw):
    with pytest.raises(ValueError):
        _ctx(**kw)


def test_match_result_matched():
    m = [{"keyword": "header"}]
    r = MatchResult(True, RULE, matches=m)
    assert r.failed_stage is None and r.matches == m


@pytest.mark.parametrize("stage", ["header", "flow", "packet", "content"])
def test_match_result_failed_stage(stage):
    r = MatchResult(False, RULE, failed_stage=stage)
    assert r.matches == [] and r.rule is RULE


def test_failed_stages_domain():
    assert FAILED_STAGES == ("header", "flow", "packet", "content")


@pytest.mark.parametrize("args, kw", [
    ((1, RULE), {"matches": [{"keyword": "header"}]}),                # matched not bool
    ((True, RULE), {}),                                               # matched without matches
    ((False, RULE), {}),                                              # unmatched without stage
    ((True, RULE), {"failed_stage": "flow"}),                         # matched with stage
    ((False, RULE), {"failed_stage": "ports"}),                       # unknown stage
    ((False, RULE), {"failed_stage": "flow", "matches": [{"keyword": "header"}]}),
])
def test_match_result_inconsistent(args, kw):
    with pytest.raises(ValueError):
        MatchResult(*args, **kw)


def test_match_result_default_list_not_shared():
    a, b = MatchResult(False, RULE, "flow"), MatchResult(False, RULE, "flow")
    a.matches.append({"keyword": "header"})
    assert b.matches == []
