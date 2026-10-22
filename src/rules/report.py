import os
from typing import Iterable

from src.logging.jsonl_logger import JSONLLogger
from src.models.rule_report import RuleRecord


def write_report(records: Iterable[RuleRecord], path: str) -> int:
    """
    Write rules_report.jsonl: one line per RuleRecord, valid rules included (reason null), so
    the report shows both what was accepted and what was rejected.

    The file is replaced, not appended to, so it always describes the latest load. Output goes
    through JSONLLogger (UTF-8, ensure_ascii=False). Returns the number of records written.
    A record that fails to serialise is counted by the logger and skipped, not raised. Errors
    on the file itself (no permission, path is a directory) still raise OSError, so the caller
    must wrap the call in try/except.
    """
    if os.path.exists(path):
        os.remove(path)
    count = 0
    with JSONLLogger(file_path=path) as out:
        for record in records:
            out.log(record)
            count += 1
        return count - out.write_errors
