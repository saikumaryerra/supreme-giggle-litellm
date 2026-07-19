"""F2: audit logging.

`emit_event` is the package-wide entry point used by auth, guardrails, and
admin tooling; the CustomLogger in logger.py handles LLM success/failure
events. Both feed the same non-blocking sink.
"""

from __future__ import annotations

from typing import Any


def emit_event(event_type: str, **fields: Any) -> None:
    """Queue an audit event without ever raising into the request path."""
    from litellm_ext.audit.sink import enqueue

    enqueue(event_type=event_type, **fields)
