"""Structured logging for the aginiti library -- added 2026-08-09 to close
a real production-readiness gap found by direct audit: `aginiti/` used
Python's `logging` module NOWHERE. Operational signal existed only as
`print()` (appropriate in experiments/*.py scripts, which are run
interactively -- left untouched) and a single `warnings.warn()` call
(`aginiti.core.llm.warn_if_parse_error`, kept exactly as-is; it serves a
distinct, still-valid purpose -- see its own docstring). Neither gives a
host application embedding Aginiti as a library any way to route,
filter, or alert on what the library is actually doing.

LIBRARY-logging best practice, not application-logging: a library must
NEVER call `logging.basicConfig()` or attach its own handlers/formatters
at import time -- doing so would silently override or fight whatever
logging configuration the HOST APPLICATION (a production service
embedding Aginiti) has already set up for itself. The only thing a
well-behaved library does by default is attach a single `NullHandler` to
its root logger, which silences Python's "No handlers could be found"
warning without emitting any output of its own
(https://docs.python.org/3/howto/logging.html#configuring-logging-for-a-library
-- the exact pattern below).

A deploying application sees this output by attaching its own handler,
e.g.:

    import logging
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    logging.getLogger("aginiti").addHandler(handler)
    logging.getLogger("aginiti").setLevel(logging.INFO)

Every logger this module hands out is a child of "aginiti" (e.g.
"aginiti.core.llm", "aginiti.campaign"), so that one line attaches to
everything -- or a caller can target just one subsystem
(`logging.getLogger("aginiti.core.llm")`) if that's all they want.

Deliberately NOT a wholesale rewrite of this codebase's print()-based
experiment scripts or its existing warnings.warn() mechanism -- this adds
a genuinely new capability (structured, leveled, filterable operational
logging for the CORE LIBRARY) without touching either of those two
already-tested, still-valid mechanisms."""
from __future__ import annotations

import logging

_ROOT_NAME = "aginiti"
logging.getLogger(_ROOT_NAME).addHandler(logging.NullHandler())


def get_logger(name: str) -> logging.Logger:
    """Returns a logger namespaced under "aginiti" -- pass the calling
    module's own short name (e.g. "core.llm", "campaign"); a name
    already starting with "aginiti" (or exactly "aginiti") is returned
    as-is, so this is safe to call defensively without double-prefixing."""
    if name == _ROOT_NAME or name.startswith(f"{_ROOT_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT_NAME}.{name}")
