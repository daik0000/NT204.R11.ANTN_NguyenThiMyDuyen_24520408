import logging
from pathlib import Path
from typing import Iterator, Optional, Tuple, Union

from src.models.rule_report import LoadReport

logger = logging.getLogger(__name__)


def iter_rule_lines(path: Union[str, Path],
                    report: Optional[LoadReport] = None) -> Iterator[Tuple[int, str]]:
    """
    Yield (line_no, text) for every rule line in a rules file; the Parser decides if it is valid.

    - Read as UTF-8 with errors="replace" (a stray byte never crashes); a leading BOM is dropped.
    - Blank / whitespace-only lines are skipped.
    - A line whose first non-blank character is '#' is skipped, including a commented-out
      rule ('# alert tcp ...'): that is the Snort convention for disabling a rule.
    - A line ending in '\\' (after rstrip) is joined with the next line: the backslash is
      removed and the pieces are joined with exactly one space (trailing blanks before the
      join and indentation of the continuation line are dropped; nothing else is touched).
      This keeps msg/content intact only when the break is outside the quotes: a break inside
      a quoted string ('"abc\\' then 'def"') yields "abc def", one extra space.
      line_no is the line where the rule starts. The first line keeps its own indentation, so
      the Parser must tolerate leading blanks.
    - Once a rule has started, every following physical line is part of it, even a blank line
      or one starting with '#': the Parser decides, we do not guess.
    - A '\\' left dangling on the last line: the gathered text is still yielded (backslash
      removed); the Parser will reject it as invalid.

    report: if given, its total_lines, blank, comment and rule_lines are incremented. They count
    LOGICAL lines (after joining), so total_lines == blank + comment + rule_lines. Only the
    rule_lines are yielded, which shows that only candidate rules reach the Parser.

    Raises OSError if the file cannot be read. This is a generator, so the error is raised on
    the FIRST iteration (next()), not at the call: the caller must put the whole for-loop in
    its try/except and count the failure in files_failed.

    Known limitation: a commented-out rule that is continued with '\\' only skips its first
    line (Snort joins first, then drops the whole block); the later lines reach the Parser,
    which rejects them as invalid.
    """
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        content = f.read()

    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines.pop()                      # text after the final newline is not a line
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in lines]

    i, n = 0, len(lines)
    while i < n:
        start = i + 1
        line = lines[i]
        i += 1
        stripped = line.strip()

        if not stripped:
            if report is not None:
                report.total_lines += 1
                report.blank += 1
            continue
        if stripped.startswith("#"):
            if report is not None:
                report.total_lines += 1
                report.comment += 1
            continue

        text = line
        while text.rstrip().endswith("\\"):
            text = text.rstrip()[:-1].rstrip()
            if i >= n:
                break                    # dangling backslash at end of file
            nxt = lines[i].lstrip()
            text = text + " " + nxt if nxt else text
            i += 1

        if report is not None:
            report.total_lines += 1
            report.rule_lines += 1
        yield start, text
