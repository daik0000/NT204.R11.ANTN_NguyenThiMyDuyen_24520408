import copy
import functools

import pytest

from src.models.rule import IpSpec, PortSpec, Rule
from src.rules.loader import load_rules
from src.rules.repository import RuleRepository
from src.rules.validator import parse_rule
from src.utils.config import DEFAULT_CONFIG


def _rule(sid):
    return Rule(action="alert", protocol="tcp", src_ip=IpSpec(any=True), src_port=PortSpec(0, 65535),
                direction="->", dst_ip=IpSpec(any=True), dst_port=PortSpec(0, 65535), msg="m", sid=sid)


def test_empty():
    repo = RuleRepository()
    assert len(repo) == 0 and repo.all() == () and not repo.frozen
    assert repo.get(1) is None and repo.order_of(1) is None and 1 not in repo
    assert list(repo) == []


def test_add_get_len_and_order_numbers():
    repo = RuleRepository()
    rules = [_rule(30), _rule(10), _rule(20)]
    assert [repo.add(r) for r in rules] == [0, 1, 2]
    assert len(repo) == 3
    assert repo.get(10) is rules[1]
    assert [repo.order_of(s) for s in (30, 10, 20)] == [0, 1, 2]
    assert 20 in repo and 99 not in repo


def test_all_keeps_insertion_order_not_sid_order():
    repo = RuleRepository()
    rules = [_rule(30), _rule(10), _rule(20), _rule(5)]
    for r in rules:
        repo.add(r)
    assert repo.all() == tuple(rules)
    assert list(repo) == rules
    assert [r.sid for r in repo.all()] == [30, 10, 20, 5]


def test_all_returns_a_snapshot():
    repo = RuleRepository()
    repo.add(_rule(1))
    snapshot = repo.all()
    repo.add(_rule(2))
    assert len(snapshot) == 1 and len(repo.all()) == 2


def test_duplicate_sid_rejected_and_repository_unchanged():
    repo = RuleRepository()
    repo.add(_rule(1))
    with pytest.raises(ValueError):
        repo.add(_rule(1))
    assert len(repo) == 1


def test_freeze_blocks_add():
    repo = RuleRepository()
    repo.add(_rule(1))
    repo.freeze()
    assert repo.frozen
    with pytest.raises(RuntimeError):
        repo.add(_rule(2))
    assert len(repo) == 1 and repo.get(2) is None


def test_freeze_is_idempotent_and_reads_still_work():
    repo = RuleRepository()
    repo.add(_rule(1))
    repo.freeze()
    repo.freeze()
    assert repo.get(1).sid == 1 and repo.all()[0].sid == 1


def test_freeze_empty_repository():
    repo = RuleRepository()
    repo.freeze()
    assert len(repo) == 0
    with pytest.raises(RuntimeError):
        repo.add(_rule(1))


def test_built_from_loader_output_keeps_file_order(tmp_path):
    a = tmp_path / "a.rules"
    b = tmp_path / "b.rules"
    head = "alert tcp any any -> any 80"
    a.write_text(f'{head} (msg:"a1"; sid:30;)\n{head} (msg:"a2"; sid:10;)\n', encoding="utf-8")
    b.write_text(f'{head} (msg:"b1"; sid:20;)\n', encoding="utf-8")
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["engine"]["rule_files"] = [{"path": str(a), "enabled": True}, {"path": str(b), "enabled": True}]
    rules, _, _ = load_rules(cfg, functools.partial(parse_rule, cfg=cfg))
    repo = RuleRepository()
    for r in rules:
        repo.add(r)
    repo.freeze()
    assert [r.sid for r in repo.all()] == [30, 10, 20]


@pytest.mark.parametrize("key", [[], {}, {1}, None, "x", 1.5])
def test_unhashable_or_foreign_keys_are_not_found(key):
    repo = RuleRepository()
    repo.add(_rule(1))
    assert repo.get(key) is None and repo.order_of(key) is None and key not in repo


def test_all_returns_the_same_tuple_after_freeze():
    repo = RuleRepository()
    repo.add(_rule(1))
    assert repo.all() is not repo.all()          # before freeze: a fresh snapshot each time
    repo.freeze()
    assert repo.all() is repo.all()
    repo.freeze()
    assert repo.all() is repo.all() and len(repo.all()) == 1


def test_iteration_is_over_a_snapshot():
    repo = RuleRepository()
    repo.add(_rule(1))
    seen = []
    for r in repo:
        seen.append(r.sid)
        repo.add(_rule(r.sid + 1))               # added during the loop: not visited
    assert seen == [1]
    assert [r.sid for r in repo.all()] == [1, 2]
