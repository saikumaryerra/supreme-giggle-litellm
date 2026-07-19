"""Prometheus metrics shared across litellm-ext modules.

Registered on the default registry, which LiteLLM's /metrics exporter serves.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

ext_auth_success_total = Counter(
    "ext_auth_success_total", "Successful authentications", ["role"]
)
ext_auth_denied_total = Counter(
    "ext_auth_denied_total", "Denied authentications", ["reason"]
)
ext_guardrail_actions_total = Counter(
    "ext_guardrail_actions_total", "Guardrail actions taken", ["action", "entity"]
)
ext_guardrail_latency_seconds = Histogram(
    "ext_guardrail_latency_seconds", "Guardrail hook latency", ["guardrail"]
)
audit_events_written_total = Counter(
    "audit_events_written_total", "Audit events written to the database"
)
audit_events_dropped_total = Counter(
    "audit_events_dropped_total", "Audit events dropped due to backpressure"
)
ext_presidio_circuit_open = Gauge(
    "ext_presidio_circuit_open", "1 when the Presidio circuit breaker is open"
)
keypool_requests_total = Counter(
    "keypool_requests_total", "Requests per provider key", ["key_id", "model", "status"]
)
keypool_tokens_total = Counter(
    "keypool_tokens_total", "Total tokens per provider key", ["key_id"]
)
keypool_cost_usd_total = Counter(
    "keypool_cost_usd_total", "Total cost (USD) per provider key", ["key_id"]
)
ext_cache_hits_total = Counter(
    "ext_cache_hits_total", "Semantic cache hits", ["team_id"]
)
ext_cache_misses_total = Counter(
    "ext_cache_misses_total", "Semantic cache misses", ["team_id"]
)
ext_qos_wait_seconds = Histogram(
    "ext_qos_wait_seconds", "Time requests waited in the QoS queue", ["tier"]
)
ext_qos_rejections_total = Counter(
    "ext_qos_rejections_total", "Requests rejected by the QoS queue", ["tier"]
)
