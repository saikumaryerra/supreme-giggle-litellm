"""§9.3: CustomGuardrail interface assertions against the installed litellm."""

from __future__ import annotations

import inspect
import typing

import pytest

pytestmark = pytest.mark.contract


class TestCustomGuardrail:
    def test_importable_from_documented_path(self) -> None:
        from litellm.integrations.custom_guardrail import CustomGuardrail  # noqa: F401

    def test_pre_call_hook_signature(self) -> None:
        from litellm.integrations.custom_guardrail import CustomGuardrail

        params = list(inspect.signature(CustomGuardrail.async_pre_call_hook).parameters)
        assert params[:5] == ["self", "user_api_key_dict", "cache", "data", "call_type"]

    def test_call_type_literals_include_completion(self) -> None:
        from litellm.integrations.custom_guardrail import CustomGuardrail

        # get_type_hints can't resolve unrelated forward refs ('DualCache'),
        # so inspect the call_type annotation directly.
        annotation = inspect.signature(
            CustomGuardrail.async_pre_call_hook
        ).parameters["call_type"].annotation
        literals = typing.get_args(annotation) or ()
        rendered = literals if literals else str(annotation)
        assert "completion" in rendered
        assert "acompletion" in rendered

    def test_post_call_success_hook_signature(self) -> None:
        from litellm.integrations.custom_guardrail import CustomGuardrail

        params = list(
            inspect.signature(CustomGuardrail.async_post_call_success_hook).parameters
        )
        assert params[:4] == ["self", "data", "user_api_key_dict", "response"]

    def test_streaming_iterator_hook_exists(self) -> None:
        # §7.3.5: required for real-time stream filtering.
        from litellm.integrations.custom_guardrail import CustomGuardrail

        hook = getattr(CustomGuardrail, "async_post_call_streaming_iterator_hook", None)
        assert hook is not None, "streaming iterator hook removed upstream"
        params = list(inspect.signature(hook).parameters)
        assert params[:4] == ["self", "user_api_key_dict", "response", "request_data"]

    def test_our_guardrails_are_valid_subclasses(self) -> None:
        from litellm.integrations.custom_guardrail import CustomGuardrail

        from litellm_ext.guardrails.injection_guardrail import InjectionGuardrail
        from litellm_ext.guardrails.lists_guardrail import ListsGuardrail
        from litellm_ext.guardrails.moderation_guardrail import ModerationGuardrail
        from litellm_ext.guardrails.pii_guardrail import PiiGuardrail
        from litellm_ext.guardrails.secrets_guardrail import SecretsGuardrail
        from litellm_ext.qos.priority import QosPriorityGuardrail

        for cls in (
            PiiGuardrail,
            SecretsGuardrail,
            InjectionGuardrail,
            ModerationGuardrail,
            ListsGuardrail,
            QosPriorityGuardrail,
        ):
            assert issubclass(cls, CustomGuardrail)
            instance = cls()
            assert hasattr(instance, "async_pre_call_hook")
