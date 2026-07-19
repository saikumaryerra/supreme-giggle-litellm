"""F8d: blocked users + banned keywords guardrail (§7B.4d). pre_call, no network.

Blocked users: reject when user_id (auth) or the request-body ``user`` field
is in the blocked/deactivation Redis sets (fed by SCIM §7B.2, manual CLI, or
an opt-out file) → 403 user_blocked before any provider call.

Banned keywords: word/phrase list from LITELLM_EXT_BANNED_KEYWORDS_PATH (one
per line, # comments), compiled to an Aho-Corasick automaton when
``pyahocorasick`` is installed (regex alternation fallback otherwise);
hot-reloads on a 60 s mtime poll. Action block (400) or mask.
"""

from __future__ import annotations

import re
import time
from typing import Any

from fastapi import HTTPException

from litellm.integrations.custom_guardrail import CustomGuardrail

from litellm_ext.audit import emit_event
from litellm_ext.guardrails.content import extract_text_slots, write_back
from litellm_ext.metrics import ext_guardrail_actions_total
from litellm_ext.redis_client import (
    BLOCKED_USERS_SET,
    DEACTIVATED_USERS_SET,
    set_contains,
)
from litellm_ext.settings import get_settings


class KeywordMatcher:
    """Banned-phrase matcher with mtime-based hot reload."""

    def __init__(self, path: str, reload_seconds: int = 60) -> None:
        self._path = path
        self._reload_seconds = reload_seconds
        self._checked_at = 0.0
        self._mtime = 0.0
        self._keywords: list[str] = []
        self._automaton: Any = None
        self._pattern: re.Pattern[str] | None = None
        self._load()

    def _load(self) -> None:
        import os

        try:
            self._mtime = os.path.getmtime(self._path)
            with open(self._path) as fh:
                self._keywords = [
                    line.strip().lower()
                    for line in fh
                    if line.strip() and not line.lstrip().startswith("#")
                ]
        except OSError:
            self._keywords = []
        self._compile()
        self._checked_at = time.monotonic()

    def _compile(self) -> None:
        self._automaton = None
        self._pattern = None
        if not self._keywords:
            return
        try:
            import ahocorasick

            automaton = ahocorasick.Automaton()
            for keyword in self._keywords:
                automaton.add_word(keyword, keyword)
            automaton.make_automaton()
            self._automaton = automaton
        except ImportError:
            alternation = "|".join(re.escape(k) for k in self._keywords)
            self._pattern = re.compile(alternation, re.I)

    def _maybe_reload(self) -> None:
        import os

        if (time.monotonic() - self._checked_at) < self._reload_seconds:
            return
        self._checked_at = time.monotonic()
        try:
            mtime = os.path.getmtime(self._path)
        except OSError:
            return
        if mtime != self._mtime:
            self._load()

    def find(self, text: str) -> list[str]:
        self._maybe_reload()
        lowered = text.lower()
        if self._automaton is not None:
            return sorted({found for _, found in self._automaton.iter(lowered)})
        if self._pattern is not None:
            return sorted({m.group().lower() for m in self._pattern.finditer(lowered)})
        return []

    def mask(self, text: str) -> str:
        for keyword in self.find(text):
            text = re.sub(re.escape(keyword), "<BANNED>", text, flags=re.I)
        return text


_matcher: KeywordMatcher | None = None


def get_matcher() -> KeywordMatcher | None:
    global _matcher
    settings = get_settings()
    if not settings.banned_keywords_path:
        return None
    if _matcher is None or _matcher._path != settings.banned_keywords_path:
        _matcher = KeywordMatcher(
            settings.banned_keywords_path, settings.blocked_users_reload_seconds
        )
    return _matcher


def reset_matcher() -> None:
    """Test helper."""
    global _matcher
    _matcher = None


class ListsGuardrail(CustomGuardrail):
    def __init__(self, *args: Any, action: str = "block", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._action = action  # keyword action: block | mask

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict | None:
        # Blocked users first: cheapest check, hard 403.
        for candidate in {
            getattr(user_api_key_dict, "user_id", None),
            data.get("user"),
        }:
            if candidate and (
                await set_contains(BLOCKED_USERS_SET, str(candidate))
                or await set_contains(DEACTIVATED_USERS_SET, str(candidate))
            ):
                ext_guardrail_actions_total.labels(
                    action="block", entity="blocked_user"
                ).inc()
                emit_event(
                    "guardrail.blocked",
                    status="blocked",
                    user_id=str(candidate),
                    team_id=getattr(user_api_key_dict, "team_id", None),
                    guardrail_info={"guardrail": "lists-shield", "reason": "blocked_user"},
                )
                raise HTTPException(status_code=403, detail={"error": "user_blocked"})

        matcher = get_matcher()
        messages = data.get("messages")
        if matcher is None or not isinstance(messages, list):
            return data

        slots = extract_text_slots(messages)
        hits: set[str] = set()
        for slot in slots:
            found = matcher.find(slot.text)
            if found and self._action == "mask":
                write_back(messages, slot, matcher.mask(slot.text))
            hits.update(found)

        if not hits:
            return data

        ext_guardrail_actions_total.labels(
            action=self._action, entity="banned_keyword"
        ).inc()
        emit_event(
            "guardrail.blocked" if self._action == "block" else "guardrail.masked",
            status="blocked" if self._action == "block" else "success",
            user_id=getattr(user_api_key_dict, "user_id", None),
            team_id=getattr(user_api_key_dict, "team_id", None),
            model_requested=data.get("model"),
            guardrail_info={
                "guardrail": "lists-shield",
                "action": self._action,
                "keyword_count": len(hits),
            },
        )
        if self._action == "block":
            raise HTTPException(
                status_code=400,
                detail={"error": "blocked_by_guardrail", "guardrail": "lists-shield"},
            )
        return data
