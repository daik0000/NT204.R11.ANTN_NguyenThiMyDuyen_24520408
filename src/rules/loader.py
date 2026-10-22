import logging
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from src.models.rule import Rule
from src.models.rule_report import LoadReport, ParseResult, RuleRecord

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


ParseFn = Callable[[str, str, int], ParseResult]


def load_rules(cfg: Dict[str, Any],
               parse_fn: ParseFn,
               extra_paths: Optional[Iterable[Union[str, Path]]] = None,
               ) -> Tuple[List[Rule], LoadReport, List[RuleRecord]]:
    """
    Load every rule file and return (rules, report, records).

    cfg: the full config from load_config(); only cfg["engine"] is used
         (rule_files, disabled_sids).
    parse_fn(text, file, line_no) -> ParseResult: injected so the Loader can be tested without
         the real Parser. It is called once per rule line, never for blank or comment lines.
    extra_paths: files from the command line (--rules). They are loaded after the configured
         files and are always enabled.

    Order: engine.rule_files in order (entries with enabled=false are not read and counted in
    report.disabled_files), then extra_paths. A path that appears twice is loaded once.

    Errors:
    - An extra path that is not an existing regular file (missing, or a directory) raises
      FileNotFoundError before anything is loaded (main.py turns it into exit code 1). A single
      str is accepted and treated as one path.
    - Any other file that cannot be read (missing, no permission, a directory, or failing part
      way) gets logger.warning and files_failed += 1, and loading continues with the next file.
      Rules already read from a file that fails part way are kept (today a file is read whole
      before any line is yielded, so this only guards future changes).
    - parse_fn raising, or not returning a ParseResult, gives invalid:internal_error for that
      line; the next line is still processed.

    Every invalid/unsupported rule is also logged as
    logger.warning("rule %s:%d rejected: %s", file, line, reason).

    Per rule line one RuleRecord is produced (valid / invalid / unsupported / disabled), and
    rule_lines == valid + invalid + unsupported + disabled.
    - A valid rule whose sid was already seen in an earlier valid rule (any file) becomes
      invalid:duplicate_sid. The duplicate check runs BEFORE the disable check, so two rules
      with the same disabled sid are not both reported as disabled.
    - A valid rule whose sid is in engine.disabled_sids is recorded as disabled and is not
      returned. Invalid and unsupported rules keep their status even if their sid is listed.
    - Only valid rules register their sid: a later valid rule with the same sid as an earlier
      invalid or unsupported one is still loaded.
    """
    engine = cfg["engine"]
    disabled_sids = set(engine["disabled_sids"])
    if isinstance(extra_paths, (str, Path)):
        extra_paths = [extra_paths]
    extras = [Path(p) for p in (extra_paths or [])]

    for p in extras:
        if not p.is_file():
            raise FileNotFoundError(f"Rule file not found: {p}")

    report = LoadReport()
    rules: List[Rule] = []
    records: List[RuleRecord] = []
    seen_sids = set()
    loaded_paths = set()

    sources: List[Path] = []
    for entry in engine["rule_files"]:
        if not entry.get("enabled", True):
            report.disabled_files += 1
            logger.info("Rule file %s is disabled in config; skipped", entry["path"])
            continue
        sources.append(Path(entry["path"]))
    sources.extend(extras)

    for path in sources:
        key = _path_key(path)
        if key in loaded_paths:
            logger.debug("Rule file %s listed twice; loaded once", path)
            continue
        loaded_paths.add(key)

        file_label = str(path)
        try:
            for line_no, text in iter_rule_lines(path, report):
                result = _safe_parse(parse_fn, text, file_label, line_no)
                _collect(result, file_label, line_no, text, report, rules, records,
                         seen_sids, disabled_sids)
        except OSError as e:
            report.files_failed += 1
            logger.warning("Cannot read rule file %s: %s", path, e)

    return rules, report, records


def _path_key(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _safe_parse(parse_fn: ParseFn, text: str, file: str, line_no: int) -> ParseResult:
    try:
        result = parse_fn(text, file, line_no)
        if not isinstance(result, ParseResult):
            raise TypeError(f"parse_fn returned {type(result).__name__}, expected ParseResult")
        return result
    except Exception as e:
        logger.warning("Parser failed on %s:%d: %s", file, line_no, e)
        return ParseResult("invalid", reason="invalid:internal_error")


def _collect(result: ParseResult, file: str, line_no: int, text: str, report: LoadReport,
             rules: List[Rule], records: List[RuleRecord], seen_sids: set,
             disabled_sids: set) -> None:
    status, reason, sid = result.status, result.reason, result.sid

    if status == "valid":
        sid = result.rule.sid
        if sid in seen_sids:
            status, reason = "invalid", "invalid:duplicate_sid"
        else:
            seen_sids.add(sid)
            if sid in disabled_sids:
                status, reason = "disabled", "disabled:sid"
            else:
                rules.append(result.rule)

    if status == "valid":
        report.valid += 1
    elif status == "invalid":
        report.invalid += 1
    elif status == "unsupported":
        report.unsupported += 1
    else:
        report.disabled += 1
    if status in ("invalid", "unsupported"):
        logger.warning("rule %s:%d rejected: %s", file, line_no, reason)
    records.append(RuleRecord(file, line_no, status, reason, sid, text))
