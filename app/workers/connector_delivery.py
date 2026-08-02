"""Connector outbox worker with leases, receipts, and bounded retry."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from typing import Protocol

import httpx
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.base import get_session_factory
from app.db.orchestration_models import AutomationOutbox

P0_DELIVERABLE_ACTIONS = frozenset({"slack.notify", "jira.issue.create", "siem.push"})


@dataclass(frozen=True)
class DeliveryReceipt:
    delivered: bool
    remote_id: str | None = None
    detail: dict | None = None
    retryable: bool = False
    error: str | None = None


class Connector(Protocol):
    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt: ...


def _retryable_status(status_code: int) -> bool:
    return status_code in {408, 429, 502, 503, 504} or status_code >= 500


def _adf(text: str) -> dict:
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": text[:32000]}]}],
    }


class SlackConnector:
    def __init__(self, webhook_url: str, timeout: float) -> None:
        self.webhook_url, self.timeout = webhook_url, timeout

    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt:
        text = item.payload.get("step_payload", {}).get("text") or item.payload.get(
            "run_context", {}
        ).get("summary")
        if not text:
            return DeliveryReceipt(False, error="Slack step requires text or run_context.summary.")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.webhook_url, json={"text": text})
        if 200 <= response.status_code < 300:
            return DeliveryReceipt(True, detail={"status_code": response.status_code})
        return DeliveryReceipt(
            False,
            retryable=_retryable_status(response.status_code),
            error=f"Slack returned {response.status_code}.",
        )


class JiraConnector:
    def __init__(self, base_url: str, email: str, token: str, timeout: float) -> None:
        self.base_url, self.auth, self.timeout = base_url.rstrip("/"), (email, token), timeout

    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt:
        data = item.payload.get("step_payload", {})
        project = item.target
        title = data.get("title") or item.payload.get("run_context", {}).get("summary")
        if not title:
            return DeliveryReceipt(False, error="Jira step requires title or run_context.summary.")

        fields = {
            "project": {"key": project},
            "summary": title,
            "issuetype": {"name": data.get("issue_type", "Task")},
        }
        if data.get("description"):
            fields["description"] = _adf(str(data["description"]))

        async with httpx.AsyncClient(timeout=self.timeout, auth=self.auth) as client:
            response = await client.post(
                f"{self.base_url}/rest/api/3/issue", json={"fields": fields}
            )
        if 200 <= response.status_code < 300:
            body = response.json()
            return DeliveryReceipt(True, remote_id=body.get("key"), detail={"id": body.get("id")})
        return DeliveryReceipt(
            False,
            retryable=_retryable_status(response.status_code),
            error=f"Jira returned {response.status_code}.",
        )


class SiemWebhookConnector:
    def __init__(self, url: str, token: str | None, timeout: float) -> None:
        self.url, self.token, self.timeout = url, token, timeout

    async def deliver(self, item: AutomationOutbox) -> DeliveryReceipt:
        headers = {"Idempotency-Key": item.idempotency_key}
        if self.token:
            headers["Authorization"] = self.token

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.url,
                json={"action": item.action, "target": item.target, "payload": item.payload},
                headers=headers,
            )
        if 200 <= response.status_code < 300:
            return DeliveryReceipt(True, detail={"status_code": response.status_code})
        return DeliveryReceipt(
            False,
            retryable=_retryable_status(response.status_code),
            error=f"SIEM endpoint returned {response.status_code}.",
        )


def registry(settings: Settings) -> dict[str, Connector]:
    result: dict[str, Connector] = {}
    if settings.slack_webhook_url:
        result["slack.notify"] = SlackConnector(
            settings.slack_webhook_url.get_secret_value(),
            settings.connector_delivery_timeout_seconds,
        )
    if settings.jira_base_url and settings.jira_email and settings.jira_api_token:
        result["jira.issue.create"] = JiraConnector(
            settings.jira_base_url,
            settings.jira_email,
            settings.jira_api_token.get_secret_value(),
            settings.connector_delivery_timeout_seconds,
        )
    if settings.siem_webhook_url:
        token = (
            settings.siem_webhook_token.get_secret_value() if settings.siem_webhook_token else None
        )
        result["siem.push"] = SiemWebhookConnector(
            settings.siem_webhook_url.get_secret_value(),
            token,
            settings.connector_delivery_timeout_seconds,
        )
    return result


def enabled_delivery_actions(settings: Settings) -> frozenset[str]:
    return frozenset(registry(settings).keys())


def retry_delay(attempts: int) -> timedelta:
    return timedelta(seconds=min(3600, 30 * (2 ** min(attempts, 7))))


class DeliveryWorker:
    def __init__(self, settings: Settings) -> None:
        self.settings, self.connectors = settings, registry(settings)

    async def claim(self, session: AsyncSession, limit: int = 20) -> list[AutomationOutbox]:
        now, token = datetime.now(UTC), token_urlsafe(24)
        pending = and_(
            AutomationOutbox.state.in_(["queued", "retry"]),
            or_(AutomationOutbox.available_at.is_(None), AutomationOutbox.available_at <= now),
            or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
        )
        abandoned = and_(
            AutomationOutbox.state == "delivering",
            or_(AutomationOutbox.lease_until.is_(None), AutomationOutbox.lease_until < now),
        )
        stmt = (
            select(AutomationOutbox)
            .where(or_(pending, abandoned))
            .order_by(AutomationOutbox.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        rows = (await session.execute(stmt)).scalars().all()
        for row in rows:
            row.state = "delivering"
            row.lease_token = token
            row.lease_until = now + timedelta(minutes=2)
        await session.commit()
        return rows

    async def deliver(self, session: AsyncSession, item: AutomationOutbox) -> None:
        connector = self.connectors.get(item.action)
        if connector is None:
            receipt = DeliveryReceipt(
                False, error=f"No enabled connector for action {item.action}."
            )
        else:
            try:
                receipt = await connector.deliver(item)
            except (httpx.HTTPError, ValueError) as exc:
                receipt = DeliveryReceipt(False, retryable=True, error=f"Connector error: {exc}")

        item.attempts += 1
        item.lease_token = None
        item.lease_until = None

        if receipt.delivered:
            item.state = "delivered"
            item.delivered_at = datetime.now(UTC)
            item.delivery_result = {"remote_id": receipt.remote_id, "detail": receipt.detail or {}}
            item.last_error = None
        elif receipt.retryable and item.attempts < self.settings.connector_max_attempts:
            item.state = "retry"
            item.available_at = datetime.now(UTC) + retry_delay(item.attempts)
            item.last_error = receipt.error
        else:
            item.state = "dead_letter"
            item.delivery_result = {"error": receipt.error, "detail": receipt.detail or {}}
            item.last_error = receipt.error

        await session.commit()

    async def run_once(self) -> int:
        factory = get_session_factory()
        async with factory() as session:
            items = await self.claim(session)
            for item in items:
                await self.deliver(session, item)
            return len(items)


async def main() -> None:
    worker = DeliveryWorker(get_settings())
    while True:
        count = await worker.run_once()
        await asyncio.sleep(1 if count else 5)


if __name__ == "__main__":
    asyncio.run(main())
