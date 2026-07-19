"""F9 (§7B.5) and F10 (§7B.6) unit tests."""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime, timedelta
from typing import Any

from litellm_ext.costgov.budgets import BudgetRule, evaluate, load_rules
from litellm_ext.costgov.chargeback import previous_month, to_csv
from litellm_ext.keyrotation.rotate import classify, clone_spec

NOW = datetime(2026, 7, 19, tzinfo=UTC)


class TestBudgetEvaluation:
    RULE = BudgetRule(monthly_usd=1000.0, alert_pcts=(80, 100), on_exhaust="enforce")

    def test_under_all_thresholds(self) -> None:
        decision = evaluate("team-a", 500.0, self.RULE, set())
        assert decision.thresholds_to_fire == ()
        assert decision.exhausted is False
        assert decision.action == "none"

    def test_crossing_80_fires_once(self) -> None:
        decision = evaluate("team-a", 850.0, self.RULE, set())
        assert decision.thresholds_to_fire == (80,)
        # Second evaluation same month: threshold already fired.
        decision2 = evaluate("team-a", 900.0, self.RULE, {80})
        assert decision2.thresholds_to_fire == ()

    def test_exhaustion_fires_both_and_enforces(self) -> None:
        decision = evaluate("team-a", 1200.0, self.RULE, set())
        assert decision.thresholds_to_fire == (80, 100)
        assert decision.exhausted is True
        assert decision.action == "enforce"

    def test_downgrade_carries_model_list(self) -> None:
        rule = BudgetRule(
            monthly_usd=100.0, on_exhaust="downgrade", downgrade_models=("gpt-4o-mini",)
        )
        decision = evaluate("team-b", 150.0, rule, {80, 100})
        assert decision.action == "downgrade"
        assert decision.downgrade_models == ("gpt-4o-mini",)
        assert decision.thresholds_to_fire == ()  # alerts fired earlier this month

    def test_load_rules_from_example_config(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        teams, users_default = load_rules(str(root / "config" / "budgets.yaml"))
        assert teams["data-science"].on_exhaust == "enforce"
        assert teams["app-backend"].downgrade_models == ("gpt-4o-mini",)
        assert users_default is not None and users_default.monthly_usd == 200


class TestChargeback:
    def test_previous_month_january_wraps(self) -> None:
        assert previous_month(datetime(2026, 1, 15, tzinfo=UTC)) == "2025-12"
        assert previous_month(datetime(2026, 7, 19, tzinfo=UTC)) == "2026-06"

    def test_csv_rendering(self) -> None:
        rows = [
            {"subject": "team-a", "model": "gpt-4o", "requests": 10, "tokens": 5000, "cost_usd": 1.23}
        ]
        out = to_csv(rows)
        assert out.splitlines()[0] == "subject,model,requests,tokens,cost_usd"
        assert "team-a" in out


def key(
    *,
    managed: bool = True,
    age_days: int = 120,
    rotation_state: str | None = None,
    expires_delta_days: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"rotation": "managed"} if managed else {}
    if rotation_state:
        metadata["rotation_state"] = rotation_state
    result: dict[str, Any] = {
        "token": "sk-test-token",
        "key_alias": "svc-账",
        "metadata": metadata,
        "created_at": (NOW - timedelta(days=age_days)).isoformat(),
        **extra,
    }
    if expires_delta_days is not None:
        result["expires"] = (NOW + timedelta(days=expires_delta_days)).isoformat()
    return result


class TestRotationClassification:
    def test_unmanaged_keys_untouched(self) -> None:
        assert classify(key(managed=False, age_days=400), NOW, 90) == "skip"

    def test_old_managed_key_rotates(self) -> None:
        assert classify(key(age_days=120), NOW, 90) == "rotate"

    def test_young_managed_key_skipped(self) -> None:
        assert classify(key(age_days=30), NOW, 90) == "skip"

    def test_mid_rotation_idempotent_skip(self) -> None:
        # Already replaced, grace period not over → re-runs must not touch it.
        assert (
            classify(key(rotation_state="replaced", expires_delta_days=3), NOW, 90)
            == "skip"
        )

    def test_grace_elapsed_deletes(self) -> None:
        assert (
            classify(key(rotation_state="replaced", expires_delta_days=-1), NOW, 90)
            == "expire_due"
        )

    def test_in_progress_state_skipped(self) -> None:
        # Idempotency: a crash mid-rotation leaves in_progress; the next run
        # must not mint a second replacement.
        assert classify(key(rotation_state="in_progress"), NOW, 90) == "skip"

    def test_epoch_created_at_parsed(self) -> None:

        epoch_key = {
            "metadata": {"rotation": "managed"},
            "created_at": (NOW - timedelta(days=200)).timestamp(),
            "token": "sk-x",
        }
        assert classify(epoch_key, NOW.replace(tzinfo=UTC), 90) == "rotate"


class TestBudgetCrossClear:
    async def test_enforce_clears_downgrade_and_vice_versa(self) -> None:
        from litellm_ext.costgov.budgets import BudgetDecision, apply_enforcement

        class FakeRedis:
            def __init__(self) -> None:
                self.exhausted: set[str] = set()
                self.downgrade: dict[str, str] = {}

            async def sadd(self, name: str, member: str) -> None:
                self.exhausted.add(member)

            async def srem(self, name: str, member: str) -> None:
                self.exhausted.discard(member)

            async def set(self, key: str, val: str) -> None:
                self.downgrade[key] = val

            async def delete(self, key: str) -> None:
                self.downgrade.pop(key, None)

        import litellm_ext.costgov.budgets as b

        fake = FakeRedis()
        b.get_redis = lambda: fake  # type: ignore[assignment]

        # First exhausted under enforce → in exhausted set.
        await apply_enforcement(
            BudgetDecision("t", 200, 100, 200, (), True, "enforce"), dry_run=False
        )
        assert "t" in fake.exhausted
        # Config flips to downgrade while still over budget → exhausted cleared.
        await apply_enforcement(
            BudgetDecision("t", 200, 100, 200, (), True, "downgrade", ("gpt-4o-mini",)),
            dry_run=False,
        )
        assert "t" not in fake.exhausted
        assert b.BUDGET_DOWNGRADE_PREFIX + "t" in fake.downgrade


class TestCloneSpec:
    def test_clone_carries_limits_and_lineage(self) -> None:
        source = key(
            models=["gpt-4o"],
            team_id="team-a",
            tpm_limit=1000,
            max_budget=50.0,
        )
        spec = clone_spec(source)
        assert spec["models"] == ["gpt-4o"]
        assert spec["team_id"] == "team-a"
        assert spec["metadata"]["rotated_from"] == "sk-test-token"
        assert "rotation_state" not in spec["metadata"]
        assert spec["metadata"]["rotation"] == "managed"  # stays managed
