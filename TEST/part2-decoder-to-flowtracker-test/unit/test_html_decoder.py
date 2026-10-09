from src.decoder.html_decoder import apply_html_decoding
from src.decoder.url_decoder import decode_form_body


def test_t02_html_entities_in_text_body():
    obj = {"value": "&lt;script&gt;alert(1)&lt;/script&gt; &#x27;ok&#x27;", "status": "OK"}
    out = apply_html_decoding(obj)
    assert out["value"] == "<script>alert(1)</script> 'ok'"
    assert out["encodings"] == ["html_entity"] and out["status"] == "OK"


def test_percent_then_entity_order_is_recorded():
    # c=%26lt%3Bb%26gt%3B  ->  percent: "&lt;b&gt;"  ->  entity: "<b>"
    out = apply_html_decoding(decode_form_body(b"c=%26lt%3Bb%26gt%3B"))
    assert out["value"] == [("c", "<b>")]
    assert out["encodings"] == ["percent", "html_entity"]


def test_text_without_entities_is_left_alone():
    obj = {"value": "plain & simple", "status": "OK"}
    out = apply_html_decoding(obj)
    assert out == {"value": "plain & simple", "status": "OK"} and "encodings" not in out


def test_skipped_or_valueless_objects_are_untouched():
    skipped = {"value": "&lt;", "status": "SKIPPED"}
    assert apply_html_decoding(skipped)["value"] == "&lt;"
    assert apply_html_decoding({"status": "OK"}) == {"status": "OK"}


def test_input_object_and_its_encodings_list_are_not_modified():
    enc = ["percent"]
    obj = {"value": "x &lt; y", "status": "OK", "encodings": enc}
    out = apply_html_decoding(obj)
    assert out is not obj and obj["value"] == "x &lt; y"
    assert enc == ["percent"] and out["encodings"] == ["percent", "html_entity"]


def test_entities_are_decoded_only_once():
    once = apply_html_decoding({"value": "&amp;lt;b&amp;gt;", "status": "OK"})
    assert once["value"] == "&lt;b&gt;"
    twice = apply_html_decoding(once)
    assert twice["value"] == "&lt;b&gt;" and twice["encodings"] == ["html_entity"]


def test_keys_and_values_of_pairs_are_both_decoded():
    out = apply_html_decoding({"value": [("a&amp;b", "1"), ("k", "&lt;&gt;")], "status": "OK"})
    assert out["value"] == [("a&b", "1"), ("k", "<>")]


def test_pairs_given_as_lists_keep_their_type_and_detect_no_change():
    unchanged = apply_html_decoding({"value": [["a", "b"]], "status": "OK"})
    assert unchanged["value"] == [["a", "b"]] and "encodings" not in unchanged
    changed = apply_html_decoding({"value": [["a", "&lt;"]], "status": "OK"})
    assert changed["value"] == [["a", "<"]]


def test_malformed_list_items_do_not_crash():
    out = apply_html_decoding({"value": [("a", "&lt;"), ("only-one",), "text", ("x", "y", "z")], "status": "OK"})
    assert out["value"][0] == ("a", "<") and out["value"][1:] == [("only-one",), "text", ("x", "y", "z")]


def test_non_string_values_are_ignored():
    assert apply_html_decoding({"value": 42, "status": "OK"}) == {"value": 42, "status": "OK"}


def test_semicolonless_legacy_entity_follows_html5():
    assert apply_html_decoding({"value": "a &amp b", "status": "OK"})["value"] == "a & b"