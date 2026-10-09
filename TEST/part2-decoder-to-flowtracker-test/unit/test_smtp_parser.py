from src.parsers.application.smtp_parser import parse_smtp

DATA = (b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"Subject: =?utf-8?B?SGVsbG8=?=\r\n"
        b" Folded-Header: yes\r\n"
        b"\r\n"
        b"SGVsbG8gV29ybGQ=")


def _app(raw):
    r = parse_smtp(raw)
    assert r["status"] == "OK", r
    return r["app_fields"]


def test_data_headers_and_body_offset():
    app = _app(DATA)
    assert app["type"] == "data"
    assert app["mime_headers"]["content-transfer-encoding"] == "base64"
    assert app["mime_headers"]["content-type"] == "text/plain; charset=utf-8"
    assert DATA[app["body_offset"]:] == b"SGVsbG8gV29ybGQ="


def test_folded_header_is_joined_to_previous_header():
    assert _app(DATA)["mime_headers"]["subject"].endswith("Folded-Header: yes")


def test_header_names_that_start_like_commands_are_still_data():
    assert _app(b"Authentication-Results: mx; spf=pass\r\nSubject: x\r\n\r\nb")["type"] == "data"
    assert _app(b"Data: x\r\n\r\nb")["type"] == "data"


def test_header_name_with_underscore_is_accepted():
    assert _app(b"X_Original_To: a@b.com\r\nSubject: x\r\n\r\nb")["type"] == "data"


def test_lf_only_line_endings_do_not_leak_body_into_headers():
    raw = b"Subject: hi\nContent-Transfer-Encoding: base64\n\nNote: this is body text\nSGVsbG8="
    app = _app(raw)
    assert "note" not in app["mime_headers"]
    assert raw[app["body_offset"]:].startswith(b"Note:")


def test_body_offset_is_none_when_headers_are_not_terminated():
    assert _app(b"Subject: hi\r\nFrom: a@b.com\r\n")["body_offset"] is None


def test_bai1_command_and_response_unchanged():
    cmd = _app(b"EHLO client.example.com\r\nMAIL FROM:<a@b.com>\r\nRCPT TO:<c@d.com>")
    assert cmd["type"] == "command"
    assert [m["command"] for m in cmd["messages"]] == ["EHLO", "MAIL FROM", "RCPT TO"]
    resp = _app(b"250-mail.example.com\r\n250 SMTPUTF8")
    assert resp["type"] == "response" and resp["messages"][-1]["is_last_line"] is True


def test_non_smtp_is_still_malformed():
    assert parse_smtp(b"SSH-2.0-OpenSSH_8.2p1\r\n")["status"] == "MALFORMED"