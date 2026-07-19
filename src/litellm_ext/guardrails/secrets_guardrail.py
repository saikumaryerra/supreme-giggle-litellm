"""F8a: credential/API-key scanning guardrail (§7B.4a).

Clean-room re-implementation against the public CustomGuardrail API (LiteLLM
gates its hide_secrets equivalent behind the enterprise license — none of
that code is referenced here).

Detection = curated regex set + Shannon entropy near secret-ish keywords.
Pure Python, no network → no fail mode needed. Default action: block.
Action mask replaces matches with <REDACTED_SECRET:type>.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from fastapi import HTTPException

from litellm.integrations.custom_guardrail import CustomGuardrail

from litellm_ext.audit import emit_event
from litellm_ext.guardrails.content import extract_text_slots, write_back
from litellm_ext.metrics import ext_guardrail_actions_total

# Curated detectors (§7B.4a). Order matters: more specific first.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack_token", re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

KEYWORD_RE = re.compile(r"\b(key|token|secret|password|credential|apikey|api_key)\b", re.I)
CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
ENTROPY_THRESHOLD = 4.5
KEYWORD_PROXIMITY = 80  # chars around a candidate searched for keywords


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def find_secrets(text: str) -> list[tuple[str, re.Match[str]]]:
    findings: list[tuple[str, re.Match[str]]] = []
    for name, pattern in SECRET_PATTERNS:
        findings.extend((name, m) for m in pattern.finditer(text))

    covered = [m.span() for _, m in findings]

    def already_found(span: tuple[int, int]) -> bool:
        return any(s <= span[0] and span[1] <= e for s, e in covered)

    # Generic high-entropy strings only count near secret-ish keywords
    # (false-positive guard: a UUID or base64 blob alone does not trigger).
    for match in CANDIDATE_RE.finditer(text):
        candidate = match.group()
        if already_found(match.span()) or UUID_RE.match(candidate):
            continue
        if shannon_entropy(candidate) <= ENTROPY_THRESHOLD:
            continue
        window_start = max(0, match.start() - KEYWORD_PROXIMITY)
        window = text[window_start : match.end() + KEYWORD_PROXIMITY]
        if KEYWORD_RE.search(window):
            findings.append(("high_entropy", match))
    return findings


def mask_secrets(text: str) -> tuple[str, dict[str, int]]:
    findings = find_secrets(text)
    counts: dict[str, int] = dict(Counter(name for name, _ in findings))
    for name, match in sorted(findings, key=lambda f: f[1].start(), reverse=True):
        text = text[: match.start()] + f"<REDACTED_SECRET:{name}>" + text[match.end() :]
    return text, counts


class SecretsGuardrail(CustomGuardrail):
    """pre_call, default_on. Configure action via guardrail_policies (block default)."""

    def __init__(self, *args: Any, action: str = "block", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._action = action

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

        slots = extract_text_slots(messages)
        total_counts: dict[str, int] = {}
        for slot in slots:
            findings = find_secrets(slot.text)
            if not findings:
                continue
            if self._action == "mask":
                masked, counts = mask_secrets(slot.text)
                write_back(messages, slot, masked)
            else:
                counts = dict(Counter(name for name, _ in findings))
            for name, count in counts.items():
                total_counts[name] = total_counts.get(name, 0) + count

        if not total_counts:
            return data

        for entity in total_counts:
            ext_guardrail_actions_total.labels(action=self._action, entity=entity).inc()
        event_type = (
            "guardrail.blocked" if self._action == "block" else "guardrail.masked"
        )
        emit_event(
            event_type,
            status="blocked" if self._action == "block" else "success",
            user_id=getattr(user_api_key_dict, "user_id", None),
            team_id=getattr(user_api_key_dict, "team_id", None),
            model_requested=data.get("model"),
            guardrail_info={
                "guardrail": "secrets-shield",
                "action": self._action,
                "entities": total_counts,  # type names and counts, never the values
            },
        )
        if self._action == "block":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "blocked_by_guardrail",
                    "guardrail": "secrets-shield",
                    "entities": sorted(total_counts),
                },
            )
        return data
