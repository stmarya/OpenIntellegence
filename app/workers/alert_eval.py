"""Run alert evaluation worker once.

Usage:
    python -m app.workers.alert_eval --triggered-by ops --tenant-id <tenant>
"""

from __future__ import annotations

import argparse
import asyncio

from app.db.base import get_session_factory
from app.services.alerts import evaluate_alert_rules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triggered-by", default="manual")
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--rule-id", type=int, default=None)
    return parser


async def _run(triggered_by: str, tenant_id: str | None, rule_id: int | None) -> None:
    async with get_session_factory()() as db:
        run = await evaluate_alert_rules(
            db,
            triggered_by=triggered_by,
            tenant_id=tenant_id,
            rule_id=rule_id,
        )
        await db.commit()
        print(
            {
                "run_id": run.id,
                "status": run.status.value,
                "evaluated_rules": run.evaluated_rules,
                "triggered_alerts": run.triggered_alerts,
                "failed_rules": run.failed_rules,
            }
        )


def main() -> None:
    args = _parser().parse_args()
    asyncio.run(_run(args.triggered_by, args.tenant_id, args.rule_id))


if __name__ == "__main__":
    main()
