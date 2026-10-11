import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent

# packet_id -> (raw URI exactly as sent, expected decoded URI). Expected values were worked out by hand
# from the percent-encoding table (see notes.md), not copied from the program output.
URIS = {
    1: ("/search?q=%27%20OR%201%3D1&name=caf%C3%A9", "/search?q=' OR 1=1&name=café"),
    2: ("/login", "/login"),
    3: ("/a+b/c%20d?x=1+2", "/a+b/c d?x=1 2"),   # '+' stays in the path, becomes a space only in the query
}


@pytest.fixture(scope="module")
def events():
    evs, _flows = run_case(CASE_DIR)              # regenerates events.jsonl / flows.jsonl from input.pcap
    return {e["packet_id"]: e for e in evs}


def test_every_packet_produces_an_ok_event(events):
    assert sorted(events) == [1, 2, 3]
    for e in events.values():
        assert e["status"] == "OK" and e["app_protocol"] == "HTTP" and e["error_info"] is None
        assert e["decode_status"] == "OK"


@pytest.mark.parametrize("pid", [1, 2, 3])
def test_raw_uri_is_untouched(events, pid):
    assert events[pid]["app_fields"]["uri"] == URIS[pid][0]


@pytest.mark.parametrize("pid", [1, 2, 3])
def test_decoded_uri_is_correct(events, pid):
    decoded = events[pid]["decoded_fields"]["uri"]
    assert decoded["value"] == URIS[pid][1] and decoded["status"] == "OK"


def test_percent_decoding_is_recorded_when_applied(events):
    assert events[1]["decoded_fields"]["uri"]["encodings"] == ["percent"]
    assert "encodings" not in events[2]["decoded_fields"]["uri"]       # nothing to decode in "/login"


def test_form_body_is_decoded_in_order(events):
    form = events[2]["decoded_fields"]["form_params"]
    assert form["value"] == [["user", "a@b.com"], ["note", "hello world"]]   # JSON turns tuples into lists
    assert form["status"] == "OK"


def test_requests_without_a_form_body_have_no_form_params(events):
    assert "form_params" not in events[1]["decoded_fields"]
    assert "form_params" not in events[3]["decoded_fields"]


def test_raw_payload_is_never_logged(events):
    assert all("payload" not in e for e in events.values())