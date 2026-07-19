"""Mock OpenAI-compatible provider for the integration stack.

Echoes chat completions; records which API key served each request
(GET /_stats) so the F4 traffic-split and cooldown criteria (§7A.8) can be
asserted. POST /_fail {"api_key": "...", "status": 429} forces a key to
start failing, driving router cooldown tests.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from typing import Any

from fastapi import FastAPI, Header, Response
from pydantic import BaseModel

app = FastAPI(title="mock-provider")
_requests_by_key: Counter[str] = Counter()
_failing: dict[str, int] = {}


class FailureRequest(BaseModel):
    api_key: str
    status: int = 429


@app.post("/_fail")
def set_failure(request: FailureRequest) -> dict[str, Any]:
    if request.status:
        _failing[request.api_key] = request.status
    else:
        _failing.pop(request.api_key, None)
    return {"failing": _failing}


@app.get("/_stats")
def stats() -> dict[str, Any]:
    return {"requests_by_key": dict(_requests_by_key)}


@app.post("/_reset")
def reset() -> dict[str, str]:
    _requests_by_key.clear()
    _failing.clear()
    return {"status": "reset"}


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
def chat(body: dict[str, Any], authorization: str = Header(default="")) -> Any:
    api_key = authorization.removeprefix("Bearer ").strip()
    _requests_by_key[api_key] += 1

    if api_key in _failing:
        return Response(
            status_code=_failing[api_key],
            content='{"error": {"message": "induced failure", "type": "mock"}}',
            media_type="application/json",
            headers={"Retry-After": "1"},
        )

    last_user = next(
        (
            m.get("content", "")
            for m in reversed(body.get("messages", []))
            if m.get("role") == "user"
        ),
        "",
    )
    if isinstance(last_user, list):
        last_user = " ".join(
            p.get("text", "") for p in last_user if isinstance(p, dict)
        )
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "mock"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": f"echo: {last_user}"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
