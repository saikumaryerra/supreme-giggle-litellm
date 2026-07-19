from __future__ import annotations

import pathlib

import pytest

from litellm_ext.settings import reset_settings_cache

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic settings for every test; individual tests override."""
    monkeypatch.setenv("LITELLM_EXT_JWT_ISSUER", "https://idp.test/realm")
    monkeypatch.setenv("LITELLM_EXT_JWT_AUDIENCE", "litellm-proxy")
    monkeypatch.setenv("LITELLM_EXT_JWKS_URL", "https://idp.test/jwks")
    monkeypatch.setenv(
        "LITELLM_EXT_RBAC_CONFIG_PATH", str(REPO_ROOT / "config" / "rbac.yaml")
    )
    monkeypatch.delenv("LITELLM_EXT_AUDIT_DB_URL", raising=False)
    monkeypatch.delenv("LITELLM_EXT_REDIS_HOST", raising=False)
    reset_settings_cache()

    from litellm_ext import redis_client
    from litellm_ext.audit import sink
    from litellm_ext.auth import jwks, rbac

    sink.reset_for_tests()
    jwks.reset_jwks_cache()
    rbac.reset_engine()
    redis_client.reset_client()

    yield

    reset_settings_cache()
