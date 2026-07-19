"""F1: virtual-key passthrough adapter (§5.3).

For non-JWT ``sk-`` tokens, delegate to LiteLLM's default auth pipeline so the
master key and pre-existing virtual keys keep working (break-glass, service
accounts). This is deliberately the ONLY module that imports LiteLLM auth
internals — an upstream rename breaks one file and is caught by
tests/contract/test_custom_auth_contract.py, not production.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request


async def default_virtual_key_auth(request: Request, api_key: str) -> Any:
    """Invoke LiteLLM's internal default auth for an sk- token."""
    from litellm.proxy.auth.user_api_key_auth import _user_api_key_auth_builder
    from litellm.proxy.common_utils.http_parsing_utils import _read_request_body

    request_data = await _read_request_body(request=request)
    return await _user_api_key_auth_builder(
        request=request,
        api_key=api_key,
        azure_api_key_header="",
        anthropic_api_key_header=None,
        google_ai_studio_api_key_header=None,
        azure_apim_header=None,
        request_data=request_data,
    )
