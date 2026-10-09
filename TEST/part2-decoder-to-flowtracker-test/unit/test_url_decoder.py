from src.decoder.url_decoder import decode_form_body, decode_query, decode_uri, percent_decode


def test_t01_percent_encoded_uri_is_decoded():
    r = decode_uri("/search?q=%27%20OR%201%3D1&name=caf%C3%A9")
    assert r["value"] == "/search?q=' OR 1=1&name=café"
    assert r["status"] == "OK" and r["encodings"] == ["percent"]


def test_plus_is_space_only_in_the_query():
    assert decode_uri("/a+b?x=1+2")["value"] == "/a+b?x=1 2"
    assert decode_uri("/a+b?x=1+2", plus_as_space_in_query=False)["value"] == "/a+b?x=1+2"
    assert decode_uri("/a+b/c")["value"] == "/a+b/c"


def test_encoded_question_mark_stays_in_the_path():
    assert decode_uri("/a%3Fb+c")["value"] == "/a?b+c"        # '+' is NOT touched: no real query string


def test_plus_alone_is_not_reported_as_percent_encoding():
    text, status, info = percent_decode("a+b", plus_as_space=True)
    assert (text, status) == ("a b", "OK") and "encodings" not in info


def test_literal_encoded_plus_stays_a_plus():
    assert percent_decode("1%2B1", plus_as_space=True)[0] == "1+1"


def test_double_encoding_is_decoded_only_when_passes_allow_it():
    assert percent_decode("%2527", passes=1)[0] == "%27"
    text, _, info = percent_decode("%2527", passes=2)
    assert text == "'" and info["encodings"] == ["percent", "percent"]


def test_plus_is_not_replayed_on_later_passes():
    assert percent_decode("%252B", passes=3, plus_as_space=True)[0] == "+"


def test_invalid_percent_sequences_are_kept_and_flagged():
    for raw in ("a%zzb", "100%", "x%1"):
        text, status, info = percent_decode(raw)
        assert text == raw and status == "PARTIAL" and info["reason"] == "invalid_percent_sequence", raw


def test_invalid_utf8_after_percent_decoding_keeps_byte_details():
    r = decode_uri("/a?q=%FF")
    assert r["status"] == "PARTIAL"
    assert r["invalid_byte_count"] == 1 and r["first_invalid_offset"] == 5   # offset in decoded "/a?q=\xff"


def test_nul_bytes_are_never_dropped_as_binary():
    assert percent_decode("%00%00%00")[:2] == ("\x00\x00\x00", "OK")
    assert decode_uri("/f?name=x%00.jpg")["value"] == "/f?name=x\x00.jpg"


def test_form_pairs_keep_order_duplicates_and_missing_values():
    r = decode_form_body(b"user=a%40b.com&note=hello+world&x=1&x=2&flag&empty=")
    assert r["value"] == [("user", "a@b.com"), ("note", "hello world"), ("x", "1"),
                          ("x", "2"), ("flag", ""), ("empty", "")]
    assert r["status"] == "OK"


def test_form_reports_invalid_bytes_across_pairs():
    r = decode_form_body(b"a=%FF&b=%FE%FD")
    assert r["status"] == "PARTIAL" and r["invalid_byte_count"] == 3


def test_empty_form_is_skipped_and_query_alias_works():
    assert decode_form_body(b"") == {"value": [], "status": "SKIPPED"}
    assert decode_query("a=b+c")["value"] == [("a", "b c")]