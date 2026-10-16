from __future__ import annotations

import json
import logging

from dabao.logging_config import JsonFormatter


def record(**extra: object) -> logging.LogRecord:
    r = logging.LogRecord("dabao.test", logging.INFO, "f.py", 1, "attempt %s done", (7,), None)
    for k, v in extra.items():
        setattr(r, k, v)
    return r


def test_json_line_has_fixed_fields_and_extras() -> None:
    line = json.loads(JsonFormatter().format(record(advisory="CVE-2024-0001", cost=0.5)))
    assert (line["level"], line["logger"], line["msg"]) == ("INFO", "dabao.test", "attempt 7 done")
    assert line["advisory"] == "CVE-2024-0001" and line["cost"] == 0.5


def test_exceptions_are_included_and_output_is_one_line() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        r = record()
        r.exc_info = sys.exc_info()
    out = JsonFormatter().format(r)
    assert "\n" not in out and "ValueError: boom" in json.loads(out)["exc"]
