import copy
import json

from src.decoder.decoder import decode_event
from src.models.event import IDSEvent
from src.utils.config import DEFAULT_CONFIG


def cfg(**decoder_overrides):
    c = copy.deepcopy(DEFAULT_CONFIG)          # same shape as load_config(): a plain dict
    c["decoder"].update(decoder_overrides)
    return c


def http_event(method="POST", uri="/a?x=1", body=b"", content_type=None, charset=None, response=False):
    start = "HTTP/1.1 200 OK" if response else f"{method} {uri} HTTP/1.1"
    head = start + "\r\nHost: a\r\n" + (f"Content-Type: {content_type}\r\n" if content_type else "") + "\r\n"
    app = {"type": "response" if response else "request", "body_offset": len(head.encode()),
           "content_type": content_type, "charset": charset}
    if not response:
        app["uri"] = uri
    return IDSEvent(1, 1.0, app_protocol="HTTP", payload=head.encode() + body, app_fields=app)


def smtp_data_event(body, cte="base64", extra_headers=None):
    head = b"Subject: x\r\n\r\n"
    headers = {"content-transfer-encoding": cte, "content-type": "text/plain; charset=utf-8"}
    headers.update(extra_headers or {})
    return IDSEvent(2, 1.0, app_protocol="SMTP", payload=head + body,
                    app_fields={"type": "data", "mime_headers": headers, "body_offset": len(head)})


def test_works_with_the_dict_returned_by_load_config():
    ev = decode_event(http_event(), cfg())
    assert ev.error_info is None and ev.decode_status == "OK"


def test_t01_uri_is_decoded_and_raw_uri_is_untouched():
    ev = http_event(method="GET", uri="/search?q=%27%20OR%201%3D1&name=caf%C3%A9")
    raw = copy.deepcopy(ev.app_fields)
    ev = decode_event(ev, cfg())
    assert ev.decoded_fields["uri"]["value"] == "/search?q=' OR 1=1&name=café"
    assert ev.app_fields == raw and ev.app_fields["uri"].startswith("/search?q=%27")
    assert ev.decode_status == "OK"


def test_uri_is_never_html_decoded():
    ev = decode_event(http_event(uri="/s?a=1&region=eu&copy=3"), cfg())
    assert ev.decoded_fields["uri"]["value"] == "/s?a=1&region=eu&copy=3"


def test_plus_as_space_in_query_follows_the_config():
    assert decode_event(http_event(uri="/a?x=1+2"), cfg()).decoded_fields["uri"]["value"] == "/a?x=1 2"
    off = decode_event(http_event(uri="/a?x=1+2"), cfg(plus_as_space_in_query=False))
    assert off.decoded_fields["uri"]["value"] == "/a?x=1+2"


def test_form_body_is_decoded_into_ordered_pairs():
    body = b"user=a%40b.com&note=hello+world&x=1&x=2"
    ev = decode_event(http_event(body=body, content_type="application/x-www-form-urlencoded"), cfg())
    assert ev.decoded_fields["form_params"]["value"] == [("user", "a@b.com"), ("note", "hello world"),
                                                         ("x", "1"), ("x", "2")]
    assert "body" not in ev.decoded_fields


def test_t02_html_entities_follow_the_content_type_list():
    body = b"&lt;script&gt;alert(1)&lt;/script&gt;"
    html_ev = decode_event(http_event(body=body, content_type="text/html", response=True), cfg())
    assert html_ev.decoded_fields["body"]["value"] == "<script>alert(1)</script>"
    assert html_ev.decoded_fields["body"]["encodings"] == ["html_entity"]
    other = decode_event(http_event(body=body, content_type="application/json", response=True), cfg())
    assert other.decoded_fields["body"]["value"] == body.decode()


def test_form_html_decoding_is_gated_by_the_same_config_list():
    body = b"c=%26lt%3Bb%26gt%3B"
    on = decode_event(http_event(body=body, content_type="application/x-www-form-urlencoded"), cfg())
    assert on.decoded_fields["form_params"]["value"] == [("c", "<b>")]
    off = decode_event(http_event(body=body, content_type="application/x-www-form-urlencoded"),
                       cfg(html_entity_content_types=["text/html"]))
    assert off.decoded_fields["form_params"]["value"] == [("c", "&lt;b&gt;")]


def test_t04_invalid_bytes_in_body_and_uri_are_partial_with_details():
    ev = decode_event(http_event(uri="/a?q=%FF", body=b"ab\xff\xfecd", content_type="text/plain",
                                 charset="utf-8"), cfg())
    body = ev.decoded_fields["body"]
    assert body["status"] == "PARTIAL" and body["invalid_byte_count"] == 2 and body["first_invalid_offset"] == 2
    assert ev.decoded_fields["uri"]["status"] == "PARTIAL"
    assert ev.decode_status == "PARTIAL" and ev.error_info is None


def test_binary_content_type_body_is_skipped_not_decoded_as_garbage_text():
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(128, 256)) * 20
    ev = decode_event(http_event(body=png, content_type="image/png", response=True), cfg())
    body = ev.decoded_fields["body"]
    assert body == {"value": "", "status": "SKIPPED", "reason": "binary_content"}
    assert ev.decode_status == "SKIPPED"


def test_missing_content_type_is_handled_as_text():
    ev = decode_event(http_event(body=b"hello", content_type=None), cfg())
    assert ev.decoded_fields["body"]["value"] == "hello" and ev.error_info is None


def test_t03_smtp_data_body_is_decoded():
    ev = decode_event(smtp_data_event(b"SGVsbG8gV29ybGQ="), cfg())
    assert ev.decoded_fields["body"]["value"] == "Hello World"
    assert ev.decode_status == "OK" and ev.error_info is None


def test_smtp_command_and_response_have_nothing_to_decode():
    for app in ({"type": "command", "messages": []}, {"type": "response", "messages": []}):
        ev = decode_event(IDSEvent(3, 1.0, app_protocol="SMTP", payload=b"EHLO x\r\n", app_fields=app), cfg())
        assert ev.decoded_fields == {} and ev.decode_status == "SKIPPED" and ev.error_info is None


def test_failed_mime_body_keeps_the_event_json_serializable():
    ev = decode_event(smtp_data_event(b"A"), cfg())
    assert ev.decode_status == "FAILED" and isinstance(ev.decoded_fields["body"]["value"], str)
    json.dumps(ev.to_dict())


def test_oversized_body_is_truncated_and_marked_partial():
    ev = decode_event(http_event(body=b"x" * 100, content_type="text/plain"), cfg(max_payload_bytes=10))
    assert len(ev.decoded_fields["body"]["value"]) == 10
    assert ev.decode_status == "PARTIAL" and "truncated_by_limit" in ev.reason


def test_oversized_smtp_body_is_truncated_and_marked_partial():
    ev = decode_event(smtp_data_event(b"SGVsbG8gV29ybGQ=" * 20), cfg(max_payload_bytes=16))
    assert ev.decode_status == "PARTIAL" and "truncated_by_limit" in ev.reason


def test_decoder_can_be_disabled_and_malformed_events_are_skipped():
    assert decode_event(http_event(), cfg(enabled=False)).decode_status is None
    bad = http_event()
    bad.status = "MALFORMED"
    out = decode_event(bad, cfg())
    assert out.decode_status is None and out.decoded_fields == {}


def test_other_protocols_and_missing_fields_do_not_crash():
    for proto, app in (("DNS", {}), ("UNKNOWN", None), (None, None), ("HTTP", None)):
        ev = decode_event(IDSEvent(4, 1.0, app_protocol=proto, app_fields=app), cfg())
        assert ev.decode_status == "SKIPPED" and ev.error_info is None, proto


def test_every_decoded_event_is_json_serializable():
    events = [http_event(body=b"a=1", content_type="application/x-www-form-urlencoded"),
              http_event(body=b"ab\xff", content_type="text/plain"),
              smtp_data_event(b"SGVsbG8=")]
    for ev in events:
        json.dumps(decode_event(ev, cfg()).to_dict())