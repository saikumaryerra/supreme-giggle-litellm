"""F9: monthly chargeback reports (§7B.5). CronJob (1st of month, 02:00):

    python -m litellm_ext.costgov.chargeback [--month YYYY-MM]

Pure read of the audit DB: per-team / per-user / per-provider-key rollups
(requests, tokens, cost by model) → CSV to LITELLM_EXT_REPORTS_BUCKET
(S3-compatible; uploaded when boto3 is available, always written locally)
+ summary email. Parquet export is stubbed behind the same interface.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import sys
from datetime import UTC, datetime
from typing import Any

from litellm_ext.costgov.notify import notify
from litellm_ext.settings import get_settings

ROLLUPS: dict[str, str] = {
    "by_team": "team_id",
    "by_user": "user_id",
    "by_key": "extra->>'key_id'",
}


def previous_month(now: datetime | None = None) -> str:
    now = now or datetime.now(tz=UTC)
    year, month = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
    return f"{year:04d}-{month:02d}"


async def rollup(conn: Any, dimension_sql: str, month: str) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        f"""
        SELECT {dimension_sql} AS subject, model_requested AS model,
               count(*) AS requests, sum(total_tokens) AS tokens,
               sum(cost_usd) AS cost_usd
        FROM audit_events
        WHERE to_char(ts, 'YYYY-MM') = $1 AND event_type = 'llm.request'
        GROUP BY 1, 2 ORDER BY 1, 5 DESC NULLS LAST
        """,
        month,
    )
    return [dict(r) for r in rows]


def to_csv(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "subject,model,requests,tokens,cost_usd\n"
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def upload(bucket: str, key: str, content: str) -> bool:
    try:
        import boto3

        boto3.client("s3").put_object(
            Bucket=bucket, Key=key, Body=content.encode(), ContentType="text/csv"
        )
        return True
    except Exception:  # noqa: BLE001 — local copy always remains
        return False


async def run(month: str, out_dir: str = "/tmp") -> dict[str, float]:
    import asyncpg

    settings = get_settings()
    dsn = settings.audit_db_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    totals: dict[str, float] = {}
    try:
        for name, dimension_sql in ROLLUPS.items():
            rows = await rollup(conn, dimension_sql, month)
            content = to_csv(rows)
            path = f"{out_dir}/chargeback-{month}-{name}.csv"
            with open(path, "w") as fh:  # noqa: ASYNC230 — batch CronJob, no event-loop pressure
                fh.write(content)
            if settings.reports_bucket:
                upload(settings.reports_bucket, f"chargeback/{month}/{name}.csv", content)
            if name == "by_team":
                totals = {
                    str(r["subject"]): float(r["cost_usd"] or 0)
                    for r in rows
                    if r["subject"]
                }
    finally:
        await conn.close()

    grand_total = round(sum(totals.values()), 2)
    await notify(
        f"LLM chargeback report {month}",
        f"Total spend ${grand_total}. Teams: "
        + ", ".join(f"{team}=${cost:.2f}" for team, cost in sorted(totals.items())),
    )
    return totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--month", default=previous_month())
    parser.add_argument("--out-dir", default="/tmp")
    args = parser.parse_args(argv)
    totals = asyncio.run(run(args.month, args.out_dir))
    print(f"chargeback {args.month}: {len(totals)} teams, ${sum(totals.values()):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
