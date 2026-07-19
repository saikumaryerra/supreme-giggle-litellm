"""§9.3: CustomLogger interface assertions against the installed litellm."""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.contract


class TestCustomLogger:
    def test_importable_from_documented_path(self) -> None:
        from litellm.integrations.custom_logger import CustomLogger  # noqa: F401

    def test_async_success_event_signature(self) -> None:
        from litellm.integrations.custom_logger import CustomLogger

        params = list(
            inspect.signature(CustomLogger.async_log_success_event).parameters
        )
        assert params == ["self", "kwargs", "response_obj", "start_time", "end_time"]

    def test_async_failure_event_signature(self) -> None:
        from litellm.integrations.custom_logger import CustomLogger

        params = list(
            inspect.signature(CustomLogger.async_log_failure_event).parameters
        )
        assert params == ["self", "kwargs", "response_obj", "start_time", "end_time"]

    def test_our_loggers_are_valid_subclasses(self) -> None:
        from litellm.integrations.custom_logger import CustomLogger

        from litellm_ext.audit.logger import audit_logger_instance
        from litellm_ext.keypool.telemetry import keypool_logger_instance

        assert isinstance(audit_logger_instance, CustomLogger)
        assert isinstance(keypool_logger_instance, CustomLogger)
