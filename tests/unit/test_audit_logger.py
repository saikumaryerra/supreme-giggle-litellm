from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from litellm_ext.audit import sink
from litellm_ext.audit.logger import AuditLogger
from litellm_ext.audit.redact import apply_body_policy, messages_to_text, sha256_text
from litellm_ext.settings import reset_settings_cache


class TestBuildEvent:
    def test_known_fields_mapped(self) -> None:
        event = sink.build_event("llm.request", user_id="u1", model_requested="gpt-4o")
        assert event["event_type"] == "llm.request"
        assert event["user_id"] == "u1"
        assert event["status"] == "success"
        assert event["event_id"]

    def test_unknown_fields_go_to_extra(self) -> None:
        event = sink.build_event("llm.request", key_id="openai-a")
        assert event["extra"] == {"key_id": "openai-a"}


class TestQueueBackpressure:
    def test_drop_oldest_when_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "LITELLM_EXT_AUDIT_DB_URL", "postgresql+asyncpg://audit@db/audit"
        )
        monkeypatch.setenv("LITELLM_EXT_AUDIT_QUEUE_SIZE", "3")
        reset_settings_cache()
        sink.reset_for_tests()

        for i in range(5):
            sink.enqueue("llm.request", request_id=f"r{i}")

        queue = sink._queue
        assert queue is not None
        kept = [queue.get_nowait()["request_id"] for _ in range(queue.qsize())]
        assert kept == ["r2", "r3", "r4"]  # oldest two dropped

    def test_enqueue_never_raises_without_db(self) -> None:
        sink.enqueue("auth.denied", status="blocked", error_class="token_expired")


class TestStdoutSink:
    def test_every_event_emits_one_json_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sink.enqueue("guardrail.blocked", status="blocked", user_id="u1")
        line = capsys.readouterr().out.strip().splitlines()[-1]
        parsed = json.loads(line)
        assert parsed["event_type"] == "guardrail.blocked"
        assert parsed["user_id"] == "u1"


class TestBodyPolicy:
    async def test_hash_policy_stores_digest_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_AUDIT_LOG_BODIES", "hash")
        reset_settings_cache()
        digest, body = await apply_body_policy("my secret prompt")
        assert digest == sha256_text("my secret prompt")
        assert body is None

    async def test_none_policy_omits_everything(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_AUDIT_LOG_BODIES", "none")
        reset_settings_cache()
        assert await apply_body_policy("prompt") == (None, None)

    async def test_full_policy_stores_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_AUDIT_LOG_BODIES", "full")
        reset_settings_cache()
        digest, body = await apply_body_policy("prompt")
        assert body == "prompt"

    def test_messages_to_text_multimodal(self) -> None:
        messages = [
            {"role": "system", "content": "sys"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "image_url", "image_url": {"url": "data:..."}},
                ],
            },
        ]
        assert messages_to_text(messages) == "sys\nhello"


def _kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "model": "gpt-4o",
        "litellm_call_id": "call-1",
        "messages": [{"role": "user", "content": "hi"}],
        "response_cost": 0.0123,
        "custom_llm_provider": "openai",
        "litellm_params": {
            "model": "openai/gpt-4o",
            "metadata": {
                "user_api_key_user_id": "user-1",
                "user_api_key_team_id": "team-a",
                "user_api_key_metadata": {"idp_roles": ["llm-engineer"]},
            },
            "model_info": {"key_id": "openai-a", "region": "eu"},
        },
    }
    base.update(overrides)
    return base


def _response() -> Any:
    return SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        choices=[SimpleNamespace(message=SimpleNamespace(content="answer"))],
    )


class TestAuditLogger:
    async def test_success_event_row(self, capsys: pytest.CaptureFixture[str]) -> None:
        logger = AuditLogger()
        start = datetime.now(tz=UTC)
        await logger.async_log_success_event(
            _kwargs(), _response(), start, start + timedelta(milliseconds=250)
        )
        event = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert event["event_type"] == "llm.request"
        assert event["user_id"] == "user-1"
        assert event["team_id"] == "team-a"
        assert event["total_tokens"] == 15
        assert event["cost_usd"] == 0.0123
        assert event["latency_ms"] == 250
        assert event["extra"]["key_id"] == "openai-a"  # F4 per-key spend
        assert event["extra"]["region"] == "eu"  # F13 residency evidence
        # hash policy default: no plaintext prompt anywhere
        assert event["prompt_body"] is None
        assert event["prompt_sha256"] is not None

    async def test_failure_event_row(self, capsys: pytest.CaptureFixture[str]) -> None:
        logger = AuditLogger()
        start = datetime.now(tz=UTC)
        error = ValueError("boom")
        await logger.async_log_failure_event(
            _kwargs(exception=error), None, start, start + timedelta(seconds=1)
        )
        event = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert event["event_type"] == "llm.failure"
        assert event["status"] == "error"
        assert event["error_class"] == "ValueError"

    async def test_callback_never_raises(self) -> None:
        logger = AuditLogger()
        # Malformed everything — must not raise into the request path.
        await logger.async_log_success_event({}, None, None, None)


class TestWriterDrain:
    async def test_shutdown_flushes_pending_batch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "LITELLM_EXT_AUDIT_DB_URL", "postgresql+asyncpg://audit@db/audit"
        )
        reset_settings_cache()
        sink.reset_for_tests()
        written: list[list[dict[str, Any]]] = []

        async def fake_flush(batch: list[dict[str, Any]]) -> None:
            written.append(list(batch))

        monkeypatch.setattr(sink, "_flush", fake_flush)
        sink.enqueue("llm.request", request_id="r1")
        sink.enqueue("llm.request", request_id="r2")
        await asyncio.sleep(0.05)  # let the writer pick events up
        await sink.shutdown()
        flat = [e["request_id"] for batch in written for e in batch]
        assert sorted(flat) == ["r1", "r2"]
