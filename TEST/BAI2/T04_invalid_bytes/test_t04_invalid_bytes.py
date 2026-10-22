import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent

# packet_id -> (field, decoded text, invalid_byte_count, first_invalid_offset). Worked out by hand (see notes.md).
# Each bad byte is shown as exactly one U+FFFD, so the text keeps one marker per bad byte.
BAD = {
    1: ("body", "abc\ufffd\ufffddef", 2, 3),      # FF FE after "abc"
    2: ("uri", "/img?name=ab\ufffdcd", 1, 12),    # %FF after the 12 bytes of "/img?name=ab"
    3: ("body", "caf\ufffd", 1, 3),               # C3 alone = half of "é"
    4: ("body", "a\x00b\ufffdc", 1, 3),           # the NUL is kept, only FF is bad
}


@pytest.fixture(scope="module")
def events():
    evs, _flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}


def test_bad_bytes_do_not_stop_the_program(events):
    assert sorted(events) == [1, 2, 3, 4, 5]           # one event per packet, including the last one
    for e in events.values():
        assert e["status"] == "OK" and e["app_protocol"] == "HTTP" and e["error_info"] is None


@pytest.mark.parametrize("pid", sorted(BAD))
def test_invalid_bytes_are_marked_partial_and_counted_exactly(events, pid):
    field, text, count, offset = BAD[pid]
    d = events[pid]["decoded_fields"][field]
    assert d["status"] == "PARTIAL"
    assert d["value"] == text
    assert d["invalid_byte_count"] == count
    assert d["first_invalid_offset"] == offset
    assert d["charset"] == "utf-8"


@pytest.mark.parametrize("pid", sorted(BAD))
def test_one_replacement_marker_per_invalid_byte(events, pid):
    field, _text, count, _offset = BAD[pid]
    assert events[pid]["decoded_fields"][field]["value"].count("\ufffd") == count


@pytest.mark.parametrize("pid", sorted(BAD))
def test_event_level_statuses_follow_the_worst_field(events, pid):
    assert events[pid]["decode_status"] == "PARTIAL"
    assert events[pid]["preprocess_status"] == "partial"


def test_raw_uri_with_percent_ff_is_untouched(events):
    assert events[2]["app_fields"]["uri"] == "/img?name=ab%FFcd"
    assert events[2]["decoded_fields"]["uri"]["encodings"] == ["percent"]


def test_stray_nul_is_not_treated_as_binary(events):
    body = events[4]["decoded_fields"]["body"]
    assert body["status"] == "PARTIAL" and body.get("reason") != "binary_content"


def test_next_valid_packet_is_decoded_normally(events):
    e = events[5]
    body = e["decoded_fields"]["body"]
    assert body["value"] == "hello" and body["status"] == "OK" and "invalid_byte_count" not in body
    assert e["decode_status"] == "OK" and e["preprocess_status"] == "valid"


def test_raw_payload_is_never_logged(events):
    assert all("payload" not in e for e in events.values())