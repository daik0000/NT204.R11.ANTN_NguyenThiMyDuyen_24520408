from src.parsers.application.http_parser import parse_http

REQ = (b"POST /s?q=%27%20OR%201%3D1 HTTP/1.1\r\n"
       b"HOST: example.com\r\n"
       b"Content-Type: Application/X-WWW-Form-Urlencoded; charset=\"UTF-8\"\r\n"
       b"Content-Length: 5\r\n\r\nabcde")


def _app(raw):
    r = parse_http(raw)
    assert r["status"] == "OK", r
    return r["app_fields"]


def test_raw_uri_is_kept_undecoded():
    app = _app(REQ)
    assert app["uri"] == "/s?q=%27%20OR%201%3D1"
    assert app["path"] == app["uri"]          # Bai 1 field unchanged


def test_body_offset_points_into_the_payload():
    assert REQ[_app(REQ)["body_offset"]:] == b"abcde"


def test_body_offset_is_none_without_header_terminator():
    assert _app(b"GET /a HTTP/1.1\r\nHost: x\r\n")["body_offset"] is None


def test_body_offset_with_empty_body_equals_payload_length():
    raw = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
    assert _app(raw)["body_offset"] == len(raw)


def test_content_type_charset_and_length():
    app = _app(REQ)
    assert app["content_type"] == "application/x-www-form-urlencoded"
    assert app["charset"] == "utf-8"
    assert app["content_length"] == 5


def test_header_pairs_keep_case_order_and_duplicates():
    raw = (b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\n"
           b"SET-COOKIE: b=2\r\n\r\n")
    app = _app(raw)
    assert app["header_pairs"] == [["Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"],
                                   ["SET-COOKIE", "b=2"]]


def test_headers_dict_keeps_original_names_like_bai1():
    assert "HOST" in _app(REQ)["headers"]


def test_empty_content_type_is_none():
    assert _app(b"GET / HTTP/1.1\r\nContent-Type: \r\n\r\n")["content_type"] is None