import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "helpers"))
from case_runner import run_case

CASE_DIR = Path(__file__).resolve().parent

# packet_id -> (raw body exactly as sent, expected decoded body). Worked out by hand from the HTML entity table.
BODIES = {
    1: ("&lt;script&gt;alert(1)&lt;/script&gt; &#x27;ok&#x27;", "<script>alert(1)</script> 'ok'"),
    4: ("1 &lt; 2 &amp;&amp; 3 &gt; 2 &amp;lt;", "1 < 2 && 3 > 2 &lt;"),   # "&amp;lt;" -> "&lt;" (decoded once)
}


@pytest.fixture(scope="module")
def events():
    evs, _flows = run_case(CASE_DIR)
    return {e["packet_id"]: e for e in evs}


def test_every_packet_produces_an_ok_event(events):
    assert sorted(events) == [1, 2, 3, 4]
    for e in events.values():
        assert e["status"] == "OK" and e["app_protocol"] == "HTTP" and e["error_info"] is None
        assert e["decode_status"] == "OK"


@pytest.mark.parametrize("pid", sorted(BODIES))
def test_html_body_is_decoded(events, pid):
    body = events[pid]["decoded_fields"]["body"]
    assert body["value"] == BODIES[pid][1] and body["status"] == "OK"
    assert body["encodings"] == ["html_entity"]


@pytest.mark.parametrize("pid", sorted(BODIES))
def test_raw_body_is_untouched(events, pid):
    assert events[pid]["app_fields"]["body_preview"] == BODIES[pid][0]


def test_form_values_are_percent_decoded_then_entity_decoded(events):
    form = events[2]["decoded_fields"]["form_params"]
    assert form["value"] == [["c", "<b>"], ["e", "&lt;"], ["n", "1"]]      # JSON turns tuples into lists
    assert form["status"] == "OK"
    assert form["encodings"] == ["percent", "html_entity"]                  # order matters


def test_raw_form_body_is_untouched(events):
    assert events[2]["app_fields"]["body_preview"] == "c=%26lt%3Bb%26gt%3B&e=%26amp%3Blt%3B&n=1"


def test_uri_is_never_html_decoded(events):
    assert events[3]["app_fields"]["uri"] == "/page?a=1&copy=2"
    uri = events[3]["decoded_fields"]["uri"]
    assert uri["value"] == "/page?a=1&copy=2"                               # not "/page?a=1©=2"
    assert "html_entity" not in uri.get("encodings", [])


def test_raw_payload_is_never_logged(events):
    assert all("payload" not in e for e in events.values())