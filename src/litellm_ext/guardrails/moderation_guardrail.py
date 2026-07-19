"""F8c: content moderation via classifier model (§7B.4c).

Default off (default_on: false); enabled per team via guardrail_policies
(moderation_enabled: true). Sends text to LITELLM_EXT_MODERATION_MODEL
(e.g. omni-moderation-latest or a self-hosted classifier exposed as a keypool
model); category→threshold map per team; blocking responses name the
category, never the content.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from litellm_ext.audit import emit_event
from litellm_ext.guardrails import policies
from litellm_ext.guardrails.circuit import classifier_circuit
from litellm_ext.guardrails.content import extract_text_slots, response_texts
from litellm_ext.guardrails.injection_guardrail import INTERNAL_MARKER, is_internal_request
from litellm_ext.metrics import ext_guardrail_actions_total
from litellm_ext.settings import FailMode, get_settings


async def moderate(text: str) -> dict[str, float] | None:
    """Category scores from the moderation model; None = unavailable."""
    settings = get_settings()
    if not settings.moderation_model or classifier_circuit.is_open:
        return None
    try:
        import litellm

        response = await litellm.amoderation(
            model=settings.moderation_model,
            input=text[:8000],
            timeout=settings.guardrail_timeout_ms / 1000.0,
            metadata={INTERNAL_MARKER: "guardrail"},
            extra_headers={INTERNAL_MARKER: "guardrail"},  # loop-guard parity
        )
        result = response.results[0]
        scores = getattr(result, "category_scores", None)
        raw = (
            scores if isinstance(scores, dict) else getattr(scores, "__dict__", {}) or {}
        )
        classifier_circuit.record_success()
        return {str(k): float(v) for k, v in dict(raw).items() if v is not None}
    except Exception:  # noqa: BLE001
        classifier_circuit.record_failure()
        return None


def violated_categories(
    scores: dict[str, float], thresholds: dict[str, float]
) -> dict[str, float]:
    out: dict[str, float] = {}
    for category, threshold in thresholds.items():
        score = scores.get(category)
        if score is not None and score >= threshold:
            out[category] = round(score, 4)
    return out


class ModerationGuardrail(CustomGuardrail):
    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict[str, Any],
        call_type: str,
    ) -> dict[str, Any] | None:
        if is_internal_request(data):
            return data
        team_policy = policies.resolve(getattr(user_api_key_dict, "team_id", None))
        if not team_policy.moderation_enabled:
            return data
        messages = data.get("messages")
        if not isinstance(messages, list):
            return data
        text = "\n".join(s.text for s in extract_text_slots(messages))
        if not text:
            return data
        await self._check(text, team_policy, user_api_key_dict, data, stage="pre_call")
        return data

    async def async_post_call_success_hook(
        self, data: dict[str, Any], user_api_key_dict: Any, response: Any
    ) -> Any:
        team_policy = policies.resolve(getattr(user_api_key_dict, "team_id", None))
        if not team_policy.moderation_enabled:
            return response
        text = "\n".join(t for _, t in response_texts(response))
        if text:
            await self._check(
                text, team_policy, user_api_key_dict, data, stage="post_call"
            )
        return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict[str, Any],
    ) -> Any:
        """Moderate streamed output too (else stream=true trivially bypasses it).

        Accumulates the full stream, then runs one moderation check at the end;
        a violation is audited and stops iteration. Like PII streaming, content
        already delivered can't be retracted — input-side moderation remains the
        hard control — but the stream is cut and the event recorded.
        """
        team_policy = policies.resolve(getattr(user_api_key_dict, "team_id", None))
        accumulated: list[str] = []
        async for chunk in response:
            for choice in getattr(chunk, "choices", []) or []:
                delta = getattr(choice, "delta", None)
                piece = getattr(delta, "content", None) if delta else None
                if piece:
                    accumulated.append(piece)
            yield chunk
        if team_policy.moderation_enabled and accumulated:
            await self._check(
                "".join(accumulated), team_policy, user_api_key_dict,
                request_data, stage="streaming",
            )

    async def _check(
        self,
        text: str,
        team_policy: policies.TeamPolicies,
        user_api_key_dict: Any,
        data: dict[str, Any],
        stage: str,
    ) -> None:
        scores = await moderate(text)
        if scores is None:
            if get_settings().guardrail_fail_mode == FailMode.closed and get_settings().moderation_model:
                raise HTTPException(
                    status_code=503,
                    detail={"error": "guardrail_unavailable", "guardrail": "moderation"},
                )
            emit_event(
                "guardrail.skipped",
                user_id=getattr(user_api_key_dict, "user_id", None),
                team_id=getattr(user_api_key_dict, "team_id", None),
                guardrail_info={"guardrail": "moderation", "stage": stage},
            )
            return

        violations = violated_categories(scores, team_policy.moderation_categories)
        if not violations:
            return
        for category in violations:
            ext_guardrail_actions_total.labels(action="block", entity=category).inc()
        emit_event(
            "guardrail.blocked",
            status="blocked",
            user_id=getattr(user_api_key_dict, "user_id", None),
            team_id=getattr(user_api_key_dict, "team_id", None),
            model_requested=data.get("model"),
            guardrail_info={
                "guardrail": "moderation",
                "stage": stage,
                "categories": violations,  # category names + scores, not content
            },
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "blocked_by_guardrail",
                "guardrail": "moderation",
                "categories": sorted(violations),
            },
        )
