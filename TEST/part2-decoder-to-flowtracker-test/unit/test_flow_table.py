from types import SimpleNamespace

import pytest

from src.flow.flow_table import FlowEntry, FlowTable


def entry(start_time=1.0):
    # A stand-in for Flow: the table only needs start_time from it.
    return FlowEntry(SimpleNamespace(start_time=start_time))


def keys(table):
    return [k for k, _ in table.items()]


def test_new_entry_has_clean_internal_state():
    e = entry(5.5)
    assert (e.fin_fwd, e.fin_bwd, e.synack_seen) == (False, False, False)
    assert e.state_changed_at == 5.5


def test_entry_requires_a_flow_with_start_time():
    with pytest.raises(AttributeError):
        FlowEntry(SimpleNamespace())


def test_add_get_len_and_get_does_not_change_order():
    t = FlowTable()
    a, b = entry(), entry()
    t.add("a", a)
    t.add("b", b)
    assert len(t) == 2 and t.get("a") is a and t.get("zzz") is None
    assert keys(t) == ["a", "b"]                      # get() must not touch


def test_touch_moves_to_end_and_changes_oldest():
    t = FlowTable()
    for k in "abc":
        t.add(k, entry())
    assert t.oldest()[0] == "a"
    t.touch("a")
    assert keys(t) == ["b", "c", "a"] and t.oldest()[0] == "b"


def test_touch_missing_key_is_a_noop():
    t = FlowTable()
    t.add("a", entry())
    t.touch("nope")
    assert keys(t) == ["a"]


def test_remove_returns_entry_or_none():
    t = FlowTable()
    e = entry()
    t.add("a", e)
    assert t.remove("a") is e and t.remove("a") is None and len(t) == 0


def test_oldest_of_empty_table_is_none():
    assert FlowTable().oldest() is None


def test_adding_an_existing_key_replaces_it_and_moves_it_to_the_end():
    t = FlowTable()
    t.add("a", entry())
    t.add("b", entry())
    new = entry(9.0)
    t.add("a", new)
    assert len(t) == 2 and t.get("a") is new and keys(t) == ["b", "a"]


def test_membership_operator():
    t = FlowTable()
    t.add("a", entry())
    assert "a" in t and "b" not in t


def test_removing_while_walking_items_is_safe():
    t = FlowTable()
    for k in "abcd":
        t.add(k, entry())
    for k, _ in t.items():          # exactly what sweep()/flush() will do
        t.remove(k)
    assert len(t) == 0