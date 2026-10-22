import pytest

from src.models.rule_report import LoadReport
from src.rules.loader import iter_rule_lines


def _read(tmp_path, data, report=None):
    p = tmp_path / "t.rules"
    p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return list(iter_rule_lines(p, report))


def test_empty_file(tmp_path):
    rep = LoadReport()
    assert _read(tmp_path, "", rep) == []
    assert rep.to_dict() == LoadReport().to_dict()


def test_blank_and_whitespace_lines_skipped(tmp_path):
    rep = LoadReport()
    assert _read(tmp_path, "\n   \n\t\nrule1\n", rep) == [(4, "rule1")]
    assert (rep.total_lines, rep.blank, rep.comment, rep.rule_lines) == (4, 3, 0, 1)


def test_comments_including_indented_and_commented_rules(tmp_path):
    rep = LoadReport()
    data = "# a comment\n   # indented\n# alert tcp any any -> any any (sid:1;)\nrule\n"
    assert _read(tmp_path, data, rep) == [(4, "rule")]
    assert (rep.comment, rep.rule_lines, rep.total_lines) == (3, 1, 4)


def test_hash_inside_rule_is_not_a_comment(tmp_path):
    assert _read(tmp_path, 'alert (msg:"a # b";)\n') == [(1, 'alert (msg:"a # b";)')]


def test_continuation_joins_with_single_space(tmp_path):
    data = 'alert tcp any any -> any 80 (msg:"x"; \\\n    content:"../"; \\\n  sid:1;)\n'
    assert _read(tmp_path, data) == [(1, 'alert tcp any any -> any 80 (msg:"x"; content:"../"; sid:1;)')]


def test_line_no_is_start_line_and_following_lines_numbered(tmp_path):
    data = "# c\n\nrule a \\\n b\nrule c\n"
    assert _read(tmp_path, data) == [(3, "rule a b"), (5, "rule c")]


def test_continuation_counts_one_logical_line(tmp_path):
    rep = LoadReport()
    _read(tmp_path, "# c\n\na \\\nb\n\n# d\nz\n", rep)
    assert (rep.total_lines, rep.blank, rep.comment, rep.rule_lines) == (6, 2, 2, 2)
    assert rep.total_lines == rep.blank + rep.comment + rep.rule_lines


def test_t01_like_counts(tmp_path):
    rep = LoadReport()
    data = ("# header\n# another\n\n"
            "alert tcp any any -> any 80 (msg:\"a\"; sid:1;)\n"
            "alert tcp any any -> any 80 (msg:\"b\"; \\\n  sid:2;)\n"
            "\n# off\n\n"
            "alert udp any any -> any 53 (msg:\"c\"; sid:3;)\n")
    assert len(_read(tmp_path, data, rep)) == 3
    assert (rep.blank, rep.comment, rep.rule_lines, rep.total_lines) == (3, 3, 3, 9)


def test_comment_or_blank_line_inside_continuation_is_part_of_rule(tmp_path):
    out = _read(tmp_path, "a \\\n# c\nb\n")
    assert out[0] == (1, "a # c")
    out = _read(tmp_path, "a \\\n\nb\n")
    assert out == [(1, "a"), (3, "b")]


def test_dangling_backslash_at_eof_still_yielded(tmp_path):
    assert _read(tmp_path, "alert tcp any any -> any any (sid:1; \\") == [(1, "alert tcp any any -> any any (sid:1;")]
    assert _read(tmp_path, "rule \\\n") == [(1, "rule")]


def test_quoted_content_is_not_stripped(tmp_path):
    assert _read(tmp_path, '  a (content:"  x  "; msg:"  y ";)  \n') == [(1, '  a (content:"  x  "; msg:"  y ";)  ')]


def test_crlf_and_no_trailing_newline(tmp_path):
    assert _read(tmp_path, "a \\\r\nb\r\nc") == [(1, "a b"), (3, "c")]


def test_non_utf8_bytes_do_not_crash(tmp_path):
    out = _read(tmp_path, b'alert (msg:"caf\xe9";)\n# \xff\xfe\nok\n')
    assert out[0][0] == 1 and "�" in out[0][1]
    assert out[1] == (3, "ok")


def test_bom_dropped(tmp_path):
    assert _read(tmp_path, b"\xef\xbb\xbfrule\n") == [(1, "rule")]


def test_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        list(iter_rule_lines(tmp_path / "nope.rules"))


def test_report_is_optional(tmp_path):
    assert _read(tmp_path, "a\n") == [(1, "a")]


def test_error_raised_on_first_iteration_not_at_call(tmp_path):
    gen = iter_rule_lines(tmp_path / "nope.rules")      # no exception yet
    with pytest.raises(OSError):
        next(gen)


def test_first_line_keeps_indentation(tmp_path):
    assert _read(tmp_path, "   rule\n") == [(1, "   rule")]
