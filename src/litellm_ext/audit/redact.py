"""F2: prompt/response body policy (§6.3 redact.py).

none → omit; hash → sha256 only; redacted → run bodies through the Presidio
anonymizer before storing; full → store verbatim (explicitly configured;
warned at startup).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from litellm_ext.settings import BodyPolicy, get_settings

logger = logging.getLogger("litellm_ext.audit")

_warned_full = False


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


async def apply_body_policy(text: str | None) -> tuple[str | None, str | None]:
    """Return (sha256, stored_body) for a prompt or response body."""
    global _warned_full
    if text is None:
        return None, None
    policy = get_settings().audit_log_bodies
    digest = sha256_text(text)
    if policy == BodyPolicy.none:
        return None, None
    if policy == BodyPolicy.hash:
        return digest, None
    if policy == BodyPolicy.redacted:
        return digest, await _redact_via_presidio(text)
    if not _warned_full:
        logger.warning(
            "AUDIT_LOG_BODIES=full: plaintext prompts/responses will be stored"
        )
        _warned_full = True
    return digest, text


async def _redact_via_presidio(text: str) -> str:
    """Anonymize through the same Presidio service the guardrail uses.

    On any failure, fall back to storing nothing rather than plaintext.
    """
    try:
        from litellm_ext.guardrails.presidio_client import get_presidio_client

        client = get_presidio_client()
        results = await client.analyze(text)
        if not results:
            return text
        return await client.anonymize(text, results)
    except Exception:  # noqa: BLE001 — never store unredacted text on failure
        logger.warning("body redaction failed; omitting body from audit event")
        return ""


def messages_to_text(messages: Any) -> str | None:
    """Flatten chat messages (string or multimodal list content) to one text."""
    if not isinstance(messages, list):
        return None
    parts: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            )
    return "\n".join(p for p in parts if p) or None
