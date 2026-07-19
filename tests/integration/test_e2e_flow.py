"""End-to-end acceptance criteria (§5.5, §6.6, §7.5, §7A.8) against the
docker-compose stack. Run:

    docker compose -f tests/integration/docker-compose.test.yaml up -d --build
    pytest tests/integration -m integration

Every test here is the oracle for a LiteLLM version bump (§9.4).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.integration

PROXY = os.environ.get("E2E_PROXY_URL", "http://localhost:4000")
IDP = os.environ.get("E2E_IDP_URL", "http://localhost:9001")
PROVIDER = os.environ.get("E2E_PROVIDER_URL", "http://localhost:9000")
AUDIT_DSN = os.environ.get(
    "E2E_AUDIT_DSN", "postgresql://audit:audit@localhost:55432/audit"
)
MASTER_KEY = "sk-master-test"


@pytest.fixture(scope="session", autouse=True)
def wait_for_stack() -> None:
    deadline = 120
    with httpx.Client(timeout=2.0) as client:
        for _ in range(deadline):
            try:
                if client.get(f"{PROXY}/health/liveliness").status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            import time

            time.sleep(1)
    pytest.skip("integration stack not running")


async def mint_token(**claims: Any) -> str:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(f"{IDP}/token", json=claims)
        resp.raise_for_status()
        return str(resp.json()["access_token"])


async def chat(token: str, model: str = "gpt-4o", content: str = "hello") -> httpx.Response:
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await client.post(
            f"{PROXY}/v1/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": content}]},
            headers={"Authorization": f"Bearer {token}"},
        )


async def audit_rows(query: str, *args: Any) -> list[Any]:
    import asyncpg

    conn = await asyncpg.connect(AUDIT_DSN)
    try:
        return list(await conn.fetch(query, *args))
    finally:
        await conn.close()


class TestF1Auth:
    async def test_valid_engineer_token_allowed_model(self) -> None:
        token = await mint_token(roles=["llm-engineer"])
        resp = await chat(token, model="gpt-4o")
        assert resp.status_code == 200, resp.text

    async def test_disallowed_model_403(self) -> None:
        token = await mint_token(roles=["llm-app-service"])  # only gpt-4o-mini
        resp = await chat(token, model="gpt-4o")
        assert resp.status_code in (401, 403), resp.text

    async def test_expired_token_401(self) -> None:
        token = await mint_token(ttl=-4000)
        assert (await chat(token)).status_code == 401

    async def test_wrong_audience_401(self) -> None:
        token = await mint_token(aud="other-api")
        assert (await chat(token)).status_code == 401

    async def test_tampered_signature_401(self) -> None:
        token = await mint_token()
        tampered = token[:-8] + "AAAAAAAA"
        assert (await chat(tampered)).status_code == 401

    async def test_unmapped_role_403(self) -> None:
        token = await mint_token(roles=["no-such-role"])
        assert (await chat(token)).status_code == 403

    async def test_master_key_passthrough_still_works(self) -> None:
        resp = await chat(MASTER_KEY, model="gpt-4o")
        assert resp.status_code == 200, resp.text


class TestF3Guardrails:
    async def test_pii_masked_before_provider(self) -> None:
        token = await mint_token()
        resp = await chat(token, content="my email is a@b.com and SSN 123-45-6789")
        assert resp.status_code == 200
        echoed = resp.json()["choices"][0]["message"]["content"]
        # Mock provider echoes what it received: raw PII must not be there.
        assert "a@b.com" not in echoed
        assert "123-45-6789" not in echoed

    async def test_secret_blocked_no_provider_call(self) -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{PROVIDER}/_reset")
        token = await mint_token()
        resp = await chat(token, content="use key AKIAIOSFODNN7EXAMPLE secret now")
        assert resp.status_code == 400
        async with httpx.AsyncClient(timeout=5.0) as client:
            stats = (await client.get(f"{PROVIDER}/_stats")).json()
        assert sum(stats["requests_by_key"].values()) == 0  # blocked pre-call


class TestF2Audit:
    async def test_llm_request_row_written(self) -> None:
        token = await mint_token(sub="audit-user")
        resp = await chat(token)
        assert resp.status_code == 200
        await asyncio.sleep(2)  # audit sink batches (500 ms flush)
        rows = await audit_rows(
            "SELECT * FROM audit_events WHERE event_type = 'llm.request' "
            "AND user_id = $1 ORDER BY ts DESC LIMIT 1",
            "audit-user",
        )
        assert rows, "no llm.request audit row"
        row = rows[0]
        assert row["total_tokens"] == 15
        assert row["prompt_sha256"] is not None
        assert row["prompt_body"] is None  # hash policy default

    async def test_guardrail_event_has_entities(self) -> None:
        token = await mint_token(sub="pii-user")
        await chat(token, content="reach me at pii@example.com")
        await asyncio.sleep(2)
        rows = await audit_rows(
            "SELECT * FROM audit_events WHERE event_type = 'guardrail.masked' "
            "ORDER BY ts DESC LIMIT 1"
        )
        assert rows


class TestF4KeyPools:
    async def test_traffic_split_roughly_two_to_one(self) -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{PROVIDER}/_reset")
        token = await mint_token()
        for _ in range(60):
            resp = await chat(token, model="gpt-4o", content="split test")
            assert resp.status_code == 200
        async with httpx.AsyncClient(timeout=5.0) as client:
            stats = (await client.get(f"{PROVIDER}/_stats")).json()["requests_by_key"]
        a = stats.get("sk-mock-key-a", 0)
        b = stats.get("sk-mock-key-b", 0)
        assert a + b == 60
        # weights 2:1 → a ≈ 40 ± generous slack for shuffle variance
        assert 0.5 <= (a / max(b, 1)) / 2.0 <= 1.6, stats

    async def test_429_key_cools_down_no_client_errors(self) -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{PROVIDER}/_reset")
            await client.post(
                f"{PROVIDER}/_fail", json={"api_key": "sk-mock-key-a", "status": 429}
            )
        token = await mint_token()
        try:
            for _ in range(10):
                resp = await chat(token, model="gpt-4o", content="cooldown test")
                assert resp.status_code == 200  # retries land on key B
        finally:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{PROVIDER}/_fail", json={"api_key": "sk-mock-key-a", "status": 0}
                )
