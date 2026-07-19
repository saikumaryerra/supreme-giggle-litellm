"""F3 acceptance criteria (§7.5) at unit level, with a fake Presidio."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from litellm_ext.guardrails import pii_guardrail as pg
from litellm_ext.guardrails.circuit import CircuitBreaker
from litellm_ext.guardrails.pii_guardrail import PiiGuardrail
from litellm_ext.guardrails.presidio_client import PresidioUnavailable
from litellm_ext.settings import reset_settings_cache

EMAIL_RE = re.compile(r"[\w.]+@[\w.]+")
SSN_RE = re.compile(r"\d{3}-\d{2}-\d{4}")


class FakePresidio:
    """Regex-backed stand-in for the Presidio analyzer/anonymizer pair."""

    def __init__(self, down: bool = False) -> None:
        self.down = down
        self.analyze_calls = 0

    async def analyze(
        self, text: str, entities: Any = None, threshold: Any = None, language: str = "en"
    ) -> list[dict[str, Any]]:
        self.analyze_calls += 1
        if self.down:
            raise PresidioUnavailable("down")
        results = []
        for match in EMAIL_RE.finditer(text):
            results.append(
                {"entity_type": "EMAIL_ADDRESS", "start": match.start(), "end": match.end(), "score": 0.9}
            )
        for match in SSN_RE.finditer(text):
            results.append(
                {"entity_type": "US_SSN", "start": match.start(), "end": match.end(), "score": 0.9}
            )
        return results

    async def analyze_batch(
        self, texts: list[str], entities: Any = None, threshold: Any = None
    ) -> list[list[dict[str, Any]]]:
        return [await self.analyze(t) for t in texts]

    async def anonymize(self, text: str, analyzer_results: list[dict[str, Any]]) -> str:
        for r in sorted(analyzer_results, key=lambda r: r["start"], reverse=True):
            text = text[: r["start"]] + f"<{r['entity_type']}>" + text[r["end"] :]
        return text


@pytest.fixture()
def fake_presidio(monkeypatch: pytest.MonkeyPatch) -> FakePresidio:
    fake = FakePresidio()
    monkeypatch.setattr(pg, "get_presidio_client", lambda: fake)
    return fake


USER = SimpleNamespace(user_id="user-1", team_id=None)


def request_data(content: Any) -> dict[str, Any]:
    return {"model": "gpt-4o", "messages": [{"role": "user", "content": content}]}


class TestMask:
    async def test_email_and_ssn_masked(
        self, fake_presidio: FakePresidio, capsys: pytest.CaptureFixture[str]
    ) -> None:
        data = request_data("my email is a@b.com and SSN 123-45-6789")
        result = await PiiGuardrail().async_pre_call_hook(USER, None, data, "completion")
        content = result["messages"][0]["content"]
        assert "<EMAIL_ADDRESS>" in content and "<US_SSN>" in content
        assert "a@b.com" not in content and "123-45-6789" not in content
        assert result["metadata"]["pii_masked"] is True  # F11 cache skip marker

        event = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert event["event_type"] == "guardrail.masked"
        assert set(event["guardrail_info"]["entities"]) == {"EMAIL_ADDRESS", "US_SSN"}

    async def test_multimodal_text_parts_masked_images_untouched(
        self, fake_presidio: FakePresidio
    ) -> None:
        image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,xx"}}
        data = request_data(
            [{"type": "text", "text": "reach me at a@b.com"}, dict(image)]
        )
        result = await PiiGuardrail().async_pre_call_hook(USER, None, data, "completion")
        parts = result["messages"][0]["content"]
        assert "<EMAIL_ADDRESS>" in parts[0]["text"]
        assert parts[1] == image  # non-text content passes untouched

    async def test_clean_prompt_no_provider_masking(self, fake_presidio: FakePresidio) -> None:
        data = request_data("what is the weather like")
        result = await PiiGuardrail().async_pre_call_hook(USER, None, data, "completion")
        assert result["messages"][0]["content"] == "what is the weather like"


class TestBlock:
    async def test_block_policy_400_machine_readable(
        self, fake_presidio: FakePresidio, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_PII_ACTION", "block")
        reset_settings_cache()
        with pytest.raises(HTTPException) as exc:
            await PiiGuardrail().async_pre_call_hook(
                USER, None, request_data("ssn 123-45-6789"), "completion"
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["error"] == "blocked_by_guardrail"
        assert exc.value.detail["entities"] == ["US_SSN"]


class TestFailModes:
    async def test_closed_returns_503(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pg, "get_presidio_client", lambda: FakePresidio(down=True))
        monkeypatch.setenv("LITELLM_EXT_GUARDRAIL_FAIL_MODE", "closed")
        reset_settings_cache()
        with pytest.raises(HTTPException) as exc:
            await PiiGuardrail().async_pre_call_hook(
                USER, None, request_data("hello a@b.com"), "completion"
            )
        assert exc.value.status_code == 503
        assert exc.value.detail["error"] == "guardrail_unavailable"

    async def test_open_passes_with_skipped_event(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(pg, "get_presidio_client", lambda: FakePresidio(down=True))
        monkeypatch.setenv("LITELLM_EXT_GUARDRAIL_FAIL_MODE", "open")
        reset_settings_cache()
        data = request_data("hello a@b.com")
        result = await PiiGuardrail().async_pre_call_hook(USER, None, data, "completion")
        assert result is data
        assert result["metadata"]["guardrail_skipped"] is True
        event = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert event["event_type"] == "guardrail.skipped"


class TestResponseSide:
    async def test_default_log_only_leaves_response(
        self, fake_presidio: FakePresidio, capsys: pytest.CaptureFixture[str]
    ) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content="contact a@b.com"))
            ]
        )
        result = await PiiGuardrail().async_post_call_success_hook(
            request_data("hi"), USER, response
        )
        assert result.choices[0].message.content == "contact a@b.com"
        event = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert event["event_type"] == "guardrail.detected"


class TestStreaming:
    async def test_block_policy_stops_stream(
        self, fake_presidio: FakePresidio, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_PII_RESPONSE_ACTION", "block")
        reset_settings_cache()

        async def stream() -> Any:
            # First chunk crosses the scan stride and contains an SSN.
            yield SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        index=0,
                        delta=SimpleNamespace(content="x" * 250 + " ssn 123-45-6789 "),
                    )
                ]
            )
            yield SimpleNamespace(
                choices=[SimpleNamespace(index=0, delta=SimpleNamespace(content="more"))]
            )

        chunks = []
        with pytest.raises(HTTPException) as exc:
            async for chunk in PiiGuardrail().async_post_call_streaming_iterator_hook(
                USER, stream(), request_data("hi")
            ):
                chunks.append(chunk)
        assert exc.value.status_code == 400
        assert exc.value.detail["stage"] == "streaming"

    async def test_clean_stream_passes_through(self, fake_presidio: FakePresidio) -> None:
        async def stream() -> Any:
            for text in ("hello ", "world"):
                yield SimpleNamespace(
                    choices=[SimpleNamespace(index=0, delta=SimpleNamespace(content=text))]
                )

        out = [
            c
            async for c in PiiGuardrail().async_post_call_streaming_iterator_hook(
                USER, stream(), request_data("hi")
            )
        ]
        assert len(out) == 2


class TestCircuitBreaker:
    def test_opens_after_threshold_and_half_opens(self) -> None:
        breaker = CircuitBreaker(failure_threshold=3, open_seconds=0.0)
        for _ in range(3):
            breaker.record_failure()
        # open_seconds=0 → immediately half-open on next check
        assert breaker.is_open is False
        breaker.record_failure()  # half-open failure re-opens instantly
        assert breaker._opened_at is not None

    def test_success_resets(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, open_seconds=30.0)
        breaker.record_failure()
        breaker.record_success()
        breaker.record_failure()
        assert breaker.is_open is False

    def test_half_open_admits_single_probe(self) -> None:
        # After the open window, only ONE caller gets through; concurrent
        # callers still see open until the probe records an outcome.
        breaker = CircuitBreaker(failure_threshold=1, open_seconds=0.0)
        breaker.record_failure()  # opens
        assert breaker.is_open is False  # first probe admitted
        assert breaker.is_open is True  # second caller blocked (probe in flight)
        assert breaker.is_open is True
        breaker.record_success()  # probe succeeded → fully closed
        assert breaker.is_open is False
