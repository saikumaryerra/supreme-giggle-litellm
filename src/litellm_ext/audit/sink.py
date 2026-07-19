"""F2: non-blocking audit sink (§6.3).

Request-path callers only build an event dict and ``put_nowait`` it onto an
asyncio.Queue. A background writer batches (N=100 or 500 ms flush) into
Postgres via asyncpg executemany, started lazily on the first event and
drained gracefully on shutdown.

Fail-open with alarm: on DB outage, tenacity backoff; when the queue fills,
drop the OLDEST event, increment audit_events_dropped_total, and emit a JSON
error line to stdout so the K8s log pipeline still captures losses. Nothing
here ever raises back into the request path.

Secondary sink: every event is also emitted as one JSON line to stdout via
the "litellm_ext.audit" logger — SIEM shipping via Fluent Bit/Vector with
zero extra code.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

from litellm_ext.audit.models import AUDIT_EVENT_COLUMNS
from litellm_ext.metrics import audit_events_dropped_total, audit_events_written_total
from litellm_ext.settings import get_settings

BATCH_SIZE = 100
FLUSH_INTERVAL_S = 0.5

class _LiveStdoutHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Resolve sys.stdout at emit time (container restarts, test capture)."""

    @property
    def stream(self) -> Any:
        return sys.stdout

    @stream.setter
    def stream(self, value: Any) -> None:
        pass


_stdout_logger = logging.getLogger("litellm_ext.audit")
if not _stdout_logger.handlers:
    _handler = _LiveStdoutHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _stdout_logger.addHandler(_handler)
    _stdout_logger.setLevel(logging.INFO)
    _stdout_logger.propagate = False

_queue: asyncio.Queue[dict[str, Any]] | None = None
_writer_task: asyncio.Task[None] | None = None


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def build_event(event_type: str, **fields: Any) -> dict[str, Any]:
    event: dict[str, Any] = {col: None for col in AUDIT_EVENT_COLUMNS}
    event.update(
        event_id=str(uuid.uuid4()),
        ts=datetime.now(tz=UTC),
        event_type=event_type,
        status=fields.pop("status", "success"),
    )
    for key, value in fields.items():
        if key in event:
            event[key] = value
        else:
            extra = event.get("extra") or {}
            extra[key] = value
            event["extra"] = extra
    return event


def enqueue(event_type: str, **fields: Any) -> None:
    """Queue an audit event. Never raises; never blocks."""
    try:
        event = build_event(event_type, **fields)
        _stdout_logger.info(json.dumps(event, default=_json_default))

        settings = get_settings()
        if not settings.audit_db_url:
            return
        queue = _get_queue(settings.audit_queue_size)
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop oldest, keep newest (§6.3): losses are counted and logged.
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            queue.put_nowait(event)
            audit_events_dropped_total.inc()
            print(
                json.dumps(
                    {"error": "audit_queue_full", "dropped": 1, "logger": "litellm_ext.audit"}
                ),
                file=sys.stdout,
                flush=True,
            )
        _ensure_writer()
    except Exception:  # noqa: BLE001 — audit is fail-open by design
        logging.getLogger(__name__).exception("audit enqueue failed")


def _get_queue(maxsize: int) -> asyncio.Queue[dict[str, Any]]:
    global _queue
    if _queue is None:
        _queue = asyncio.Queue(maxsize=maxsize)
    return _queue


def _ensure_writer() -> None:
    global _writer_task
    if _writer_task is None or _writer_task.done():
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # not in an event loop (unit tests, CLI) — stdout sink only
        _writer_task = loop.create_task(_writer_loop())


async def _writer_loop() -> None:
    assert _queue is not None
    batch: list[dict[str, Any]] = []
    while True:
        try:
            timeout = FLUSH_INTERVAL_S if batch else None
            try:
                event = await asyncio.wait_for(_queue.get(), timeout=timeout)
                batch.append(event)
            except TimeoutError:
                pass
            if len(batch) >= BATCH_SIZE or (batch and _queue.empty()):
                await _flush(batch)
                batch = []
        except asyncio.CancelledError:
            if batch:
                await _flush(batch)
            while not _queue.empty():
                batch.append(_queue.get_nowait())
                if len(batch) >= BATCH_SIZE:
                    await _flush(batch)
                    batch = []
            if batch:
                await _flush(batch)
            raise
        except Exception:  # noqa: BLE001
            logging.getLogger(__name__).exception("audit writer iteration failed")
            await asyncio.sleep(1)


async def _flush(batch: list[dict[str, Any]]) -> None:
    from tenacity import retry, stop_after_attempt, wait_exponential

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=0.5, max=8),
        reraise=True,
    )
    async def _write() -> None:
        conn = await _connect()
        try:
            columns = ", ".join(AUDIT_EVENT_COLUMNS)
            placeholders = ", ".join(f"${i + 1}" for i in range(len(AUDIT_EVENT_COLUMNS)))
            rows = [
                tuple(_to_db(event.get(col)) for col in AUDIT_EVENT_COLUMNS)
                for event in batch
            ]
            await conn.executemany(
                f"INSERT INTO audit_events ({columns}) VALUES ({placeholders})", rows
            )
        finally:
            await conn.close()

    try:
        await _write()
        audit_events_written_total.inc(len(batch))
    except Exception:  # noqa: BLE001 — DB outage: events already went to stdout
        audit_events_dropped_total.inc(len(batch))
        print(
            json.dumps(
                {
                    "error": "audit_db_write_failed",
                    "dropped": len(batch),
                    "logger": "litellm_ext.audit",
                }
            ),
            file=sys.stdout,
            flush=True,
        )


def _to_db(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=_json_default)
    return value


async def _connect() -> Any:
    import asyncpg

    dsn = get_settings().audit_db_url.replace("postgresql+asyncpg://", "postgresql://")
    return await asyncpg.connect(dsn, timeout=5.0)


async def shutdown() -> None:
    """Graceful drain on shutdown signal."""
    global _writer_task
    if _writer_task is not None and not _writer_task.done():
        _writer_task.cancel()
        try:
            await _writer_task
        except asyncio.CancelledError:
            pass
    _writer_task = None


def reset_for_tests() -> None:
    global _queue, _writer_task
    _queue = None
    _writer_task = None
