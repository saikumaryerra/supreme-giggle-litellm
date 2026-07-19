"""Shared circuit breaker for guardrail external calls (§7.3.6, §7B.4).

After 5 consecutive failures, open for 30 s: external calls are skipped and
the configured fail mode applies instantly, protecting request latency. Used
by the Presidio client and the injection/moderation classifiers.
"""

from __future__ import annotations

import time

from litellm_ext.metrics import ext_presidio_circuit_open

FAILURE_THRESHOLD = 5
OPEN_SECONDS = 30.0


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = FAILURE_THRESHOLD,
        open_seconds: float = OPEN_SECONDS,
        track_metric: bool = False,
    ) -> None:
        self._threshold = failure_threshold
        self._open_seconds = open_seconds
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._probing = False  # a half-open probe is in flight
        self._track_metric = track_metric

    @property
    def is_open(self) -> bool:
        # A probe is already out: hold everyone else until it reports back, so a
        # batched asyncio.gather can't hit a just-recovered service all at once.
        if self._probing:
            return True
        if self._opened_at is None:
            return False
        if (time.monotonic() - self._opened_at) >= self._open_seconds:
            # Half-open: admit exactly ONE probe. Keep _opened_at set so that,
            # until the probe records an outcome, the circuit still reads open
            # for concurrent callers (guarded by the _probing check above).
            self._probing = True
            return False
        return True

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None
        self._probing = False
        self._set_metric(0)

    def record_failure(self) -> None:
        was_probing = self._probing
        self._probing = False
        self._consecutive_failures += 1
        # Re-open on a fresh failure, or immediately if a half-open probe failed.
        if was_probing or self._consecutive_failures >= self._threshold:
            self._opened_at = time.monotonic()
            self._set_metric(1)

    def _set_metric(self, value: int) -> None:
        if self._track_metric:
            ext_presidio_circuit_open.set(value)


presidio_circuit = CircuitBreaker(track_metric=True)
classifier_circuit = CircuitBreaker()
