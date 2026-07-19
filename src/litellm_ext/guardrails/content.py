"""Shared message-content access for guardrails.

Handles both string content and multimodal list content
({"type": "text", "text": ...} items). Only text parts are scanned or
modified; images and other parts pass through untouched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class TextSlot:
    """A mutable reference to one text span inside data["messages"]."""

    message_index: int
    part_index: int | None  # None = plain string content
    text: str


def extract_text_slots(
    messages: list[dict[str, Any]], skip_system: bool = False
) -> list[TextSlot]:
    slots: list[TextSlot] = []
    for m_idx, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        if skip_system and message.get("role") == "system":
            continue
        content = message.get("content")
        if isinstance(content, str) and content:
            slots.append(TextSlot(m_idx, None, content))
        elif isinstance(content, list):
            for p_idx, part in enumerate(content):
                if (
                    isinstance(part, dict)
                    and part.get("type") == "text"
                    and part.get("text")
                ):
                    slots.append(TextSlot(m_idx, p_idx, str(part["text"])))
    return slots


def write_back(messages: list[dict[str, Any]], slot: TextSlot, new_text: str) -> None:
    if slot.part_index is None:
        messages[slot.message_index]["content"] = new_text
    else:
        messages[slot.message_index]["content"][slot.part_index]["text"] = new_text


def response_texts(response: Any) -> list[tuple[int, str]]:
    """(choice_index, text) for each string message content in a response."""
    out: list[tuple[int, str]] = []
    for idx, choice in enumerate(getattr(response, "choices", []) or []):
        message = getattr(choice, "message", None)
        content = getattr(message, "content", None) if message else None
        if isinstance(content, str) and content:
            out.append((idx, content))
    return out
