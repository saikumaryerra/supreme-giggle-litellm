"""F9: budget evaluation + enforcement (§7B.5). Runs as a 5-minute CronJob:

    python -m litellm_ext.costgov.budgets [--dry-run]

Month-to-date spend per team/user comes from the audit DB; budgets.yaml is
the source of truth. Alert thresholds fire once per subject per month
(budget_alert_state unique index). Enforcement is soft-real-time by design:
auth reads the Redis sets on every request, this job refreshes them.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import yaml

from litellm_ext.audit import emit_event
from litellm_ext.costgov.notify import notify
from litellm_ext.redis_client import (
    BUDGET_DOWNGRADE_PREFIX,
    BUDGET_EXHAUSTED_SET,
    get_redis,
)
from litellm_ext.settings import get_settings


@dataclass(frozen=True)
class BudgetRule:
    monthly_usd: float
    alert_pcts: tuple[int, ...] = (80, 100)
    on_exhaust: str = "alert_only"  # enforce | alert_only | downgrade
    downgrade_models: tuple[str, ...] = ()


@dataclass(frozen=True)
class BudgetDecision:
    subject: str
    spend: float
    budget: float
    pct: float
    thresholds_to_fire: tuple[int, ...]
    exhausted: bool
    action: str
    downgrade_models: tuple[str, ...] = ()


def load_rules(path: str) -> tuple[dict[str, BudgetRule], BudgetRule | None]:
    with open(path) as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}
    teams = {
        name: BudgetRule(
            monthly_usd=float(cfg["monthly_usd"]),
            alert_pcts=tuple(cfg.get("alert_pcts", [80, 100])),
            on_exhaust=str(cfg.get("on_exhaust", "alert_only")),
            downgrade_models=tuple(cfg.get("downgrade_models", [])),
        )
        for name, cfg in (raw.get("teams") or {}).items()
    }
    users_default = None
    if raw.get("users_default"):
        cfg = raw["users_default"]
        users_default = BudgetRule(
            monthly_usd=float(cfg["monthly_usd"]),
            alert_pcts=tuple(cfg.get("alert_pcts", [80, 100])),
            on_exhaust=str(cfg.get("on_exhaust", "alert_only")),
        )
    return teams, users_default


def evaluate(
    subject: str,
    spend: float,
    rule: BudgetRule,
    already_fired: set[int],
) -> BudgetDecision:
    pct = (spend / rule.monthly_usd * 100.0) if rule.monthly_usd else 0.0
    to_fire = tuple(
        t for t in sorted(rule.alert_pcts) if pct >= t and t not in already_fired
    )
    exhausted = pct >= 100.0
    return BudgetDecision(
        subject=subject,
        spend=round(spend, 2),
        budget=rule.monthly_usd,
        pct=round(pct, 1),
        thresholds_to_fire=to_fire,
        exhausted=exhausted,
        action=rule.on_exhaust if exhausted else "none",
        downgrade_models=rule.downgrade_models,
    )


def current_month() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m")


async def month_to_date_spend(conn: Any) -> tuple[dict[str, float], dict[str, float]]:
    team_rows = await conn.fetch(
        "SELECT team_id, sum(cost_usd) AS spend FROM audit_events "
        "WHERE ts >= date_trunc('month', now()) AND cost_usd IS NOT NULL "
        "AND team_id IS NOT NULL GROUP BY 1"
    )
    user_rows = await conn.fetch(
        "SELECT user_id, sum(cost_usd) AS spend FROM audit_events "
        "WHERE ts >= date_trunc('month', now()) AND cost_usd IS NOT NULL "
        "AND user_id IS NOT NULL GROUP BY 1"
    )
    return (
        {r["team_id"]: float(r["spend"]) for r in team_rows},
        {r["user_id"]: float(r["spend"]) for r in user_rows},
    )


async def top_models(conn: Any, team_id: str, limit: int = 3) -> list[str]:
    rows = await conn.fetch(
        "SELECT model_requested, sum(cost_usd) AS spend FROM audit_events "
        "WHERE ts >= date_trunc('month', now()) AND team_id = $1 "
        "AND cost_usd IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT $2",
        team_id,
        limit,
    )
    return [r["model_requested"] for r in rows if r["model_requested"]]


async def fired_thresholds(conn: Any, subject: str, month: str) -> set[int]:
    rows = await conn.fetch(
        "SELECT threshold_pct FROM budget_alert_state WHERE subject = $1 AND month = $2",
        subject,
        month,
    )
    return {r["threshold_pct"] for r in rows}


async def mark_fired(conn: Any, subject: str, month: str, threshold: int) -> None:
    await conn.execute(
        "INSERT INTO budget_alert_state (subject, month, threshold_pct, fired_at) "
        "VALUES ($1, $2, $3, now()) ON CONFLICT DO NOTHING",
        subject,
        month,
        threshold,
    )


async def apply_enforcement(decision: BudgetDecision, dry_run: bool) -> None:
    redis = get_redis()
    if redis is None or dry_run:
        return
    # Always clear the state that doesn't match the current action, so a
    # config change (enforce↔downgrade) or a return under budget can't leave a
    # stale EXHAUSTED entry that auth checks first and hard-429s on.
    if decision.exhausted and decision.action == "enforce":
        await redis.sadd(BUDGET_EXHAUSTED_SET, decision.subject)
        await redis.delete(BUDGET_DOWNGRADE_PREFIX + decision.subject)
    elif decision.exhausted and decision.action == "downgrade":
        await redis.set(
            BUDGET_DOWNGRADE_PREFIX + decision.subject,
            ",".join(decision.downgrade_models),
        )
        await redis.srem(BUDGET_EXHAUSTED_SET, decision.subject)
    else:
        # Under budget again (new month / raised budget) or alert_only: clear.
        await redis.srem(BUDGET_EXHAUSTED_SET, decision.subject)
        await redis.delete(BUDGET_DOWNGRADE_PREFIX + decision.subject)


async def run(dry_run: bool = False) -> list[BudgetDecision]:
    import asyncpg

    settings = get_settings()
    rules, users_default = load_rules(settings.budgets_config_path)
    dsn = settings.audit_db_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    decisions: list[BudgetDecision] = []
    month = current_month()
    try:
        # Align the SQL month boundary with current_month()'s Python UTC so
        # date_trunc/to_char don't drift by the DB session timezone at rollover.
        await conn.execute("SET TIME ZONE 'UTC'")
        team_spend, user_spend = await month_to_date_spend(conn)
        for team, rule in rules.items():
            spend = team_spend.get(team, 0.0)
            fired = await fired_thresholds(conn, team, month)
            decision = evaluate(team, spend, rule, fired)
            decisions.append(decision)

            for threshold in decision.thresholds_to_fire:
                models = await top_models(conn, team)
                if not dry_run:
                    await mark_fired(conn, team, month, threshold)
                    await notify(
                        f"LLM budget alert: {team} at {decision.pct}%",
                        f"Team {team} spent ${decision.spend} of ${decision.budget} "
                        f"({decision.pct}%, {threshold}% threshold). "
                        f"Top models: {', '.join(models) or 'n/a'}",
                    )
                emit_event(
                    "admin.action",
                    team_id=team,
                    extra={
                        "action": "budget_alert",
                        "threshold_pct": threshold,
                        "spend": decision.spend,
                    },
                )
            await apply_enforcement(decision, dry_run)

        # Per-user default budgets (alert-only; enforcement stays team-scoped).
        if users_default is not None:
            for user_id, spend in user_spend.items():
                subject = f"user:{user_id}"
                fired = await fired_thresholds(conn, subject, month)
                decision = evaluate(subject, spend, users_default, fired)
                for threshold in decision.thresholds_to_fire:
                    if not dry_run:
                        await mark_fired(conn, subject, month, threshold)
                        await notify(
                            f"LLM budget alert: user {user_id} at {decision.pct}%",
                            f"User {user_id} spent ${decision.spend} of "
                            f"${decision.budget} ({decision.pct}%, {threshold}%).",
                        )
                    emit_event(
                        "admin.action",
                        user_id=user_id,
                        extra={
                            "action": "user_budget_alert",
                            "threshold_pct": threshold,
                            "spend": decision.spend,
                        },
                    )
    finally:
        await conn.close()
    return decisions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    decisions = asyncio.run(run(dry_run=args.dry_run))
    for decision in decisions:
        print(
            f"{decision.subject}: ${decision.spend}/{decision.budget} "
            f"({decision.pct}%) action={decision.action}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
