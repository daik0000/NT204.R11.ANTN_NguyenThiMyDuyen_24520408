import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent

# packet_id -> (decoded body, body status, encodings, reason, event decode_status, preprocess_status)
# Worked out by hand (see notes.md), not copied from the program output.
EXPECTED = {
    1: ("Café IDS", "OK", ["base64"], None, "OK", "valid"),
    2: ("Xin chào café, 1+1=2, softbreak", "OK", ["quoted-printable"], None, "OK", "valid"),
    3: ("Hello", "PARTIAL", ["base64"], "malformed_base64_cleaned", "PARTIAL", "partial"),
    4: ("A", "FAILED", None, "base64_decode_failed", "FAILED", "partial"),     # undecodable -> raw text kept
    5: ("Hello World", "OK", ["base64"], None, "OK", "valid"),
}


@pytest.fixture(scope="module")
def events():
    evs, _flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}


def test_every_packet_is_parsed_as_smtp_data(events):
    assert sorted(events) == [1, 2, 3, 4, 5]          # damaged packets did not stop the run
    for e in events.values():
        assert e["status"] == "OK" and e["app_protocol"] == "SMTP" and e["error_info"] is None
        assert e["app_fields"]["type"] == "data"


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_decoded_body_value_and_status(events, pid):
    value, status, _enc, _reason, _dec, _prep = EXPECTED[pid]
    body = events[pid]["decoded_fields"]["body"]
    assert body["value"] == value and body["status"] == status


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_encodings_and_reason(events, pid):
    _v, _s, encodings, reason, _dec, _prep = EXPECTED[pid]
    body = events[pid]["decoded_fields"]["body"]
    if encodings is not None:
        assert body["encodings"] == encodings
    assert body.get("reason") == reason


@pytest.mark.parametrize("pid", sorted(EXPECTED))
def test_event_level_statuses(events, pid):
    _v, _s, _e, _r, decode_status, preprocess_status = EXPECTED[pid]
    assert events[pid]["decode_status"] == decode_status
    assert events[pid]["preprocess_status"] == preprocess_status


def test_end_of_data_marker_is_not_part_of_the_decoded_text(events):
    for pid in (1, 2, 5):
        value = events[pid]["decoded_fields"]["body"]["value"]
        assert "\r\n.\r\n" not in value and not value.endswith(".")


def test_transfer_encoding_header_variant_is_recognised(events):
    assert events[5]["app_fields"]["mime_headers"]["content-transfer-encoding"] == "BASE64"   # raw header kept
    assert events[5]["decoded_fields"]["body"]["encodings"] == ["base64"]


def test_charset_of_the_text_is_reported(events):
    assert events[1]["decoded_fields"]["body"].get("charset") == "utf-8"


def test_raw_payload_is_never_logged(events):
    assert all("payload" not in e for e in events.values())