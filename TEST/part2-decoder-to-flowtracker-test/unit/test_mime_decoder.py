import base64
import json

from src.decoder.mime_decoder import decode_mime_body
from src.models.event import IDSEvent

HEAD = b"Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\n"
OFFSET = len(HEAD)


def _decode(body: bytes, cte="base64", content_type=None):
    headers = {"content-transfer-encoding": cte}
    if content_type:
        headers["content-type"] = content_type
    return decode_mime_body(HEAD + body, OFFSET, headers)


def test_t03_base64_single_line():
    r = _decode(b"SGVsbG8gV29ybGQ=")
    assert (r["value"], r["status"]) == ("Hello World", "OK")
    assert r["encodings"] == ["base64"]


def test_base64_wrapped_every_76_columns_is_not_partial():
    text = b"The quick brown fox jumps over the lazy dog. " * 6
    wrapped = base64.encodebytes(text)                       # CRLF/LF every 76 characters
    assert b"\n" in wrapped.strip()
    r = _decode(wrapped)
    assert r["value"] == text.decode() and r["status"] == "OK" and "reason" not in r


def test_base64_with_smtp_end_of_data_marker():
    r = _decode(b"SGVsbG8gV29ybGQ=\r\n.\r\n")
    assert (r["value"], r["status"]) == ("Hello World", "OK")


def test_transfer_encoding_header_value_is_case_and_space_insensitive():
    r = _decode(b"SGVsbG8=", cte=" BASE64 ")
    assert (r["value"], r["status"]) == ("Hello", "OK")


def test_quoted_printable_with_soft_line_break():
    r = _decode(b"caf=C3=A9 soft=\r\nbreak", cte="quoted-printable")
    assert r["value"] == "café softbreak" and r["status"] == "OK"
    assert r["encodings"] == ["quoted-printable"]


def test_charset_from_content_type_is_applied_after_transfer_decoding():
    r = _decode(b"caf=E9", cte="quoted-printable", content_type='text/plain; charset="ISO-8859-1"')
    assert r["value"] == "café" and r["status"] == "OK" and r["charset"] == "iso-8859-1"


def test_malformed_base64_is_cleaned_and_marked_partial():
    r = _decode(b"SGVs!bG8")                                  # junk character and missing padding
    assert r["value"] == "Hello" and r["status"] == "PARTIAL"
    assert r["reason"] == "malformed_base64_cleaned"


def test_undecodable_base64_is_failed_and_keeps_raw_text_as_str():
    r = _decode(b"A")
    assert r["status"] == "FAILED" and r["reason"] == "base64_decode_failed"
    assert isinstance(r["value"], str) and r["value"] == "A"
    json.dumps(IDSEvent(1, 1.0, decoded_fields={"body": r}).to_dict())   # must stay JSON-serializable


def test_plain_7bit_text_is_ok_not_skipped():
    for cte in ("7bit", "8bit", "binary", ""):
        r = _decode(b"Hello", cte=cte)
        assert (r["value"], r["status"]) == ("Hello", "OK") and "encodings" not in r, cte


def test_unsupported_transfer_encoding_is_skipped_with_reason():
    r = _decode(b"begin 644 file", cte="x-uuencode")
    assert r["status"] == "SKIPPED" and r["reason"] == "unsupported_encoding:x-uuencode"
    assert r["value"] == "begin 644 file"


def test_base64_binary_attachment_is_skipped_as_binary():
    r = _decode(base64.b64encode(b"\x00\x01\x02\x00\x00\x00\x03" * 10))
    assert r["status"] == "SKIPPED" and r["reason"] == "binary_content" and r["encodings"] == ["base64"]


def test_invalid_utf8_after_base64_decoding_is_partial_with_details():
    r = _decode(base64.b64encode(b"ab\xff\xfecd"))
    assert r["status"] == "PARTIAL" and r["invalid_byte_count"] == 2 and r["first_invalid_offset"] == 2


def test_empty_body_or_bad_offset_is_skipped():
    assert decode_mime_body(HEAD, OFFSET, {})["reason"] == "empty_payload"
    assert decode_mime_body(b"", 0, {})["status"] == "SKIPPED"
    assert decode_mime_body(HEAD + b"x", None, {})["status"] == "SKIPPED"

def test_final_period_of_the_text_is_not_mistaken_for_the_end_of_data_marker():
    assert _decode(b"Hello World.", cte="7bit")["value"] == "Hello World."
    assert _decode(b"Hello World.\r\n", cte="7bit")["value"] == "Hello World.\r\n"
    assert _decode(b"See you.\r\n", cte="quoted-printable")["value"] == "See you.\r\n"


def test_real_end_of_data_marker_is_still_removed():
    assert _decode(b"Hello\r\n.\r\n", cte="7bit")["value"] == "Hello"
    assert _decode(b"Hello\n.\n", cte="7bit")["value"] == "Hello"