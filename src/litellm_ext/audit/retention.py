"""F2: retention purge job (§6.5). Runs as the daily audit-retention CronJob:

    python -m litellm_ext.audit.retention [--days N] [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from litellm_ext.settings import get_settings


async def purge(days: int, dry_run: bool) -> int:
    import asyncpg

    settings = get_settings()
    dsn = settings.audit_db_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    try:
        if dry_run:
            count = await conn.fetchval(
                "SELECT count(*) FROM audit_events WHERE ts < now() - $1::interval",
                f"{days} days",
            )
            print(f"dry-run: {count} events older than {days} days")
            return int(count or 0)
        result = await conn.execute(
            "DELETE FROM audit_events WHERE ts < now() - $1::interval", f"{days} days"
        )
        deleted = int(result.split()[-1])
        print(f"purged {deleted} events older than {days} days")
        return deleted
    finally:
        await conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=get_settings().audit_retention_days)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    asyncio.run(purge(args.days, args.dry_run))
    return 0


if __name__ == "__main__":
    sys.exit(main())
