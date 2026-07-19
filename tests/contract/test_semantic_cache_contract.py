"""§7B.7 decision rule as a contract test: prefer LiteLLM's native semantic
cache. While these pass, the proxy template's ``cache_params.type:
redis-semantic`` is the implementation and cache/semantic_cache.py stays a
fallback. If an upgrade breaks them, switch the config to the custom hook
pair (the safety rules in should_cache apply to both)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.contract


class TestNativeSemanticCache:
    def test_cache_type_string_supported(self) -> None:
        from litellm.types.caching import LiteLLMCacheType

        assert "redis-semantic" in {t.value for t in LiteLLMCacheType}

    def test_redis_semantic_cache_class_exists(self) -> None:
        from litellm.caching.redis_semantic_cache import RedisSemanticCache  # noqa: F401

    def test_cache_constructor_accepts_semantic_params(self) -> None:
        import inspect

        from litellm.caching.caching import Cache

        params = inspect.signature(Cache.__init__).parameters
        assert "similarity_threshold" in params
        assert "ttl" in params
