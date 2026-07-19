"""F3: PiiGuardrail(CustomGuardrail) — Presidio-backed PII masking (§7.3).

Registered in proxy config (§7.4) with mode [pre_call, post_call]; the
streaming iterator hook covers real-time response filtering (§7.3.5).

Actions per policy: mask (anonymize in place), block (400 with entity types),
log_only. Audit events record entity *types and counts*, never raw values.
Failure mode per GUARDRAIL_FAIL_MODE: closed → 503 guardrail_unavailable;
open → pass with a guardrail.skipped audit event. A shared circuit breaker
(5 failures → open 30 s) keeps Presidio outages off the hot path.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any, AsyncGenerator

from fastapi import HTTPException

from litellm.integrations.custom_guardrail import CustomGuardrail

from litellm_ext.audit import emit_event
from litellm_ext.guardrails import policies
from litellm_ext.guardrails.content import (
    extract_text_slots,
    response_texts,
    write_back,
)
from litellm_ext.guardrails.presidio_client import (
    PresidioUnavailable,
    get_presidio_client,
)
from litellm_ext.metrics import (
    ext_guardrail_actions_total,
    ext_guardrail_latency_seconds,
)
from litellm_ext.settings import FailMode, PiiAction, get_settings

STREAM_SCAN_WINDOW = 512  # re-scan the tail this many chars per flush boundary
STREAM_SCAN_STRIDE = 256  # scan every time this much new text accumulated


def _team_id(user_api_key_dict: Any) -> str | None:
    return getattr(user_api_key_dict, "team_id", None)


def _entity_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(r["entity_type"] for r in results))


class PiiGuardrail(CustomGuardrail):
    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict | None:
        messages = data.get("messages")
        if not isinstance(messages, list):
            return data

        team = _team_id(user_api_key_dict)
        policy = policies.resolve(team).pii
        slots = extract_text_slots(messages, skip_system=policy.skip_system_message)
        if not slots:
            return data

        started = time.monotonic()
        try:
            results = await get_presidio_client().analyze_batch(
                [s.text for s in slots], policy.entities, policy.threshold
            )
        except PresidioUnavailable:
            return self._handle_unavailable(user_api_key_dict, data, "pre_call")
        finally:
            ext_guardrail_latency_seconds.labels(guardrail="pii").observe(
                time.monotonic() - started
            )

        all_hits = [r for per_text in results for r in per_text]
        if not all_hits:
            return data

        counts = _entity_counts(all_hits)
        if policy.action == PiiAction.block:
            self._audit("guardrail.blocked", user_api_key_dict, data, counts, "block")
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "blocked_by_guardrail",
                    "guardrail": "pii-shield",
                    "entities": sorted(counts),
                },
            )

        if policy.action == PiiAction.mask:
            client = get_presidio_client()
            for slot, slot_results in zip(slots, results):
                if not slot_results:
                    continue
                try:
                    masked = await client.anonymize(slot.text, slot_results)
                except PresidioUnavailable:
                    return self._handle_unavailable(user_api_key_dict, data, "pre_call")
                write_back(messages, slot, masked)
            data["metadata"] = data.get("metadata") or {}
            data["metadata"]["pii_masked"] = True  # F11: masked requests never cached
            self._audit("guardrail.masked", user_api_key_dict, data, counts, "mask")
            return data

        self._audit("guardrail.detected", user_api_key_dict, data, counts, "log_only")
        return data

    async def async_post_call_success_hook(
        self, data: dict, user_api_key_dict: Any, response: Any
    ) -> Any:
        team = _team_id(user_api_key_dict)
        policy = policies.resolve(team).pii
        texts = response_texts(response)
        if not texts:
            return response

        try:
            results = await get_presidio_client().analyze_batch(
                [t for _, t in texts], policy.entities, policy.threshold
            )
        except PresidioUnavailable:
            self._handle_unavailable(user_api_key_dict, data, "post_call")
            return response

        all_hits = [r for per_text in results for r in per_text]
        if not all_hits:
            return response
        counts = _entity_counts(all_hits)

        if policy.response_action == PiiAction.block:
            self._audit("guardrail.blocked", user_api_key_dict, data, counts, "block")
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "blocked_by_guardrail",
                    "guardrail": "pii-shield",
                    "stage": "response",
                    "entities": sorted(counts),
                },
            )
        if policy.response_action == PiiAction.mask:
            client = get_presidio_client()
            for (choice_idx, text), slot_results in zip(texts, results):
                if not slot_results:
                    continue
                try:
                    masked = await client.anonymize(text, slot_results)
                except PresidioUnavailable:
                    self._handle_unavailable(user_api_key_dict, data, "post_call")
                    return response
                response.choices[choice_idx].message.content = masked
            self._audit("guardrail.masked", user_api_key_dict, data, counts, "mask")
            return response

        self._audit("guardrail.detected", user_api_key_dict, data, counts, "log_only")
        return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[Any, None]:
        """Real-time stream scanning (§7.3.5).

        Accumulates chunks per choice and re-scans the tail STREAM_SCAN_WINDOW
        chars at each flush boundary. Block policy stops iteration mid-stream;
        mask policy on streams degrades to log_only (already-yielded text
        cannot be retracted) — input-side masking remains the hard guarantee.
        """
        team = _team_id(user_api_key_dict)
        policy = policies.resolve(team).pii
        accumulated: dict[int, str] = {}
        unscanned: dict[int, int] = {}

        async for chunk in response:
            for choice in getattr(chunk, "choices", []) or []:
                delta = getattr(choice, "delta", None)
                text = getattr(delta, "content", None) if delta else None
                if not text:
                    continue
                idx = getattr(choice, "index", 0) or 0
                accumulated[idx] = accumulated.get(idx, "") + text
                unscanned[idx] = unscanned.get(idx, 0) + len(text)

                if unscanned[idx] >= STREAM_SCAN_STRIDE:
                    await self._scan_stream_tail(
                        accumulated[idx], policy, user_api_key_dict, request_data
                    )
                    unscanned[idx] = 0
            yield chunk

        for idx, text in accumulated.items():
            if unscanned.get(idx, 0) > 0:
                await self._scan_stream_tail(
                    text, policy, user_api_key_dict, request_data
                )

    async def _scan_stream_tail(
        self, text: str, policy: policies.PiiPolicy, user_api_key_dict: Any, data: dict
    ) -> None:
        window = text[-STREAM_SCAN_WINDOW:]
        try:
            results = await get_presidio_client().analyze(
                window, policy.entities, policy.threshold
            )
        except PresidioUnavailable:
            self._handle_unavailable(user_api_key_dict, data, "streaming")
            return
        if not results:
            return
        counts = _entity_counts(results)
        if policy.response_action == PiiAction.block:
            self._audit("guardrail.blocked", user_api_key_dict, data, counts, "block")
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "blocked_by_guardrail",
                    "guardrail": "pii-shield",
                    "stage": "streaming",
                    "entities": sorted(counts),
                },
            )
        self._audit("guardrail.detected", user_api_key_dict, data, counts, "log_only")

    def _handle_unavailable(
        self, user_api_key_dict: Any, data: dict, stage: str
    ) -> dict | None:
        settings = get_settings()
        if settings.guardrail_fail_mode == FailMode.closed:
            emit_event(
                "guardrail.blocked",
                status="blocked",
                user_id=getattr(user_api_key_dict, "user_id", None),
                team_id=_team_id(user_api_key_dict),
                guardrail_info={"guardrail": "pii-shield", "reason": "unavailable"},
            )
            raise HTTPException(
                status_code=503,
                detail={"error": "guardrail_unavailable", "guardrail": "pii-shield"},
            )
        emit_event(
            "guardrail.skipped",
            status="success",
            user_id=getattr(user_api_key_dict, "user_id", None),
            team_id=_team_id(user_api_key_dict),
            model_requested=data.get("model"),
            guardrail_info={"guardrail": "pii-shield", "stage": stage, "reason": "unavailable"},
        )
        data.setdefault("metadata", {})["guardrail_skipped"] = True
        return data

    def _audit(
        self,
        event_type: str,
        user_api_key_dict: Any,
        data: dict,
        entity_counts: dict[str, int],
        action: str,
    ) -> None:
        for entity in entity_counts:
            ext_guardrail_actions_total.labels(action=action, entity=entity).inc()
        emit_event(
            event_type,
            status="blocked" if action == "block" else "success",
            user_id=getattr(user_api_key_dict, "user_id", None),
            team_id=_team_id(user_api_key_dict),
            model_requested=data.get("model"),
            guardrail_info={
                "guardrail": "pii-shield",
                "action": action,
                "entities": entity_counts,  # types and counts — never raw values
            },
        )
