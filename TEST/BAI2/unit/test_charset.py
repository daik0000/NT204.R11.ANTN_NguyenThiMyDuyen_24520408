import time

from src.decoder.charset import decode_bytes


def test_empty_payload_is_skipped():
    assert decode_bytes(b"") == ("", "SKIPPED", {"reason": "empty_payload"})


def test_valid_utf8_is_ok():
    text, status, info = decode_bytes("café".encode("utf-8"))
    assert (text, status) == ("café", "OK")
    assert info == {"charset": "utf-8"}


def test_invalid_bytes_are_replaced_counted_and_located():
    text, status, info = decode_bytes(b"ab\xff\xfecd")
    assert status == "PARTIAL"
    assert text == "ab\ufffd\ufffdcd"                    # length kept, nothing silently dropped
    assert info["invalid_byte_count"] == 2
    assert info["first_invalid_offset"] == 2


def test_truncated_multibyte_sequence_counts_bytes_not_replacement_chars():
    # b"\xe2\x82" is one incomplete sequence, but it is 2 invalid BYTES
    _, status, info = decode_bytes(b"ab\xe2\x82cd")
    assert status == "PARTIAL" and info["invalid_byte_count"] == 2 and info["first_invalid_offset"] == 2


def test_legitimate_replacement_char_is_not_counted_as_invalid():
    _, status, info = decode_bytes("a\ufffdb".encode("utf-8") + b"\xff")
    assert status == "PARTIAL" and info["invalid_byte_count"] == 1


def test_charset_aliases_and_quotes_are_accepted():
    for hint, label in [("UTF8", "utf-8"), ('"utf-8"', "utf-8"), (" ascii ", "us-ascii"),
                        ("US-ASCII", "us-ascii"), ("latin1", "iso-8859-1")]:
        _, _, info = decode_bytes(b"abc", hint)
        assert info["charset"] == label and "charset_unsupported" not in info, hint


def test_unsupported_charset_falls_back_to_utf8_and_is_reported():
    text, status, info = decode_bytes("é".encode("utf-8"), "windows-1252")
    assert (text, status) == ("é", "OK")
    assert info == {"charset_unsupported": "windows-1252", "charset": "utf-8"}


def test_unsupported_hint_in_log_is_truncated():
    _, _, info = decode_bytes(b"abc", "x" * 500)
    assert len(info["charset_unsupported"]) == 64


def test_ascii_declared_but_non_ascii_bytes_is_partial():
    _, status, info = decode_bytes("café".encode("utf-8"), "us-ascii")
    assert status == "PARTIAL" and info["invalid_byte_count"] == 2


def test_iso_8859_1_is_only_used_when_declared():
    assert decode_bytes(b"caf\xe9", "iso-8859-1")[:2] == ("café", "OK")
    assert decode_bytes(b"caf\xe9")[1] == "PARTIAL"       # no silent latin-1 fallback


def test_dense_nul_bytes_are_skipped_as_binary():
    assert decode_bytes(b"\x89PNG\x00\x00\x00\x0d\x00\x00")[2] == {"reason": "binary_content"}


def test_a_few_nul_bytes_do_not_hide_invalid_bytes():
    # sample payload of the SMTP garbage test: only 2 NUL out of 22 bytes
    _, status, info = decode_bytes(b"\xff\xfe\x00\x00Ransomware_Garbage")
    assert status == "PARTIAL" and info["invalid_byte_count"] == 2


def test_large_all_invalid_payload_is_fast():
    start = time.perf_counter()
    _, status, info = decode_bytes(b"\xff" * 65536)
    assert status == "PARTIAL" and info["invalid_byte_count"] == 65536
    assert time.perf_counter() - start < 1.0