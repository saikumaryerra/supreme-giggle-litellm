"""F2: audit DB schema (§6.2) as SQLAlchemy models (Alembic migrates them).

The app role gets INSERT-only on audit_events (tamper resistance); auditors
get a separate read-only role. See migrations/ and deploy/k8s/audit-db.yaml.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Identity, Index, Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, default=uuid.uuid4
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # llm.request | llm.failure | auth.denied | guardrail.blocked |
    # guardrail.masked | guardrail.skipped | admin.action | admin.access_requested
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    request_id: Mapped[str | None] = mapped_column(Text)  # litellm call id
    user_id: Mapped[str | None] = mapped_column(Text)
    user_email: Mapped[str | None] = mapped_column(Text)
    team_id: Mapped[str | None] = mapped_column(Text)
    idp_roles: Mapped[Any | None] = mapped_column(JSONB)
    model_requested: Mapped[str | None] = mapped_column(Text)
    model_actual: Mapped[str | None] = mapped_column(Text)  # after routing
    provider: Mapped[str | None] = mapped_column(Text)
    route: Mapped[str | None] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(INET)
    status: Mapped[str] = mapped_column(Text, nullable=False)  # success | error | blocked
    error_class: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[float | None] = mapped_column(Numeric(12, 6))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    prompt_sha256: Mapped[str | None] = mapped_column(Text)  # always, per body policy
    response_sha256: Mapped[str | None] = mapped_column(Text)
    prompt_body: Mapped[str | None] = mapped_column(Text)  # only redacted/full policies
    response_body: Mapped[str | None] = mapped_column(Text)
    guardrail_info: Mapped[Any | None] = mapped_column(JSONB)  # entities, action taken
    extra: Mapped[Any | None] = mapped_column(JSONB)

    __table_args__ = (
        Index("ix_audit_events_ts", "ts"),
        Index("ix_audit_events_user_ts", "user_id", "ts"),
        Index("ix_audit_events_team_ts", "team_id", "ts"),
        Index("ix_audit_events_type_ts", "event_type", "ts"),
    )


class BudgetAlertState(Base):
    """F9: fire each alert threshold once per team per month (§7B.5)."""

    __tablename__ = "budget_alert_state"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False)  # team id or user id
    month: Mapped[str] = mapped_column(Text, nullable=False)  # e.g. 2026-07
    threshold_pct: Mapped[int] = mapped_column(Integer, nullable=False)
    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index(
            "ux_budget_alert_once", "subject", "month", "threshold_pct", unique=True
        ),
    )


class ScimUser(Base):
    """F6: SCIM resource state for reconciliation (§7B.2)."""

    __tablename__ = "scim_users"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    external_id: Mapped[str | None] = mapped_column(Text)
    user_name: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(nullable=False, default=True)
    raw: Mapped[Any | None] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScimGroup(Base):
    __tablename__ = "scim_groups"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    members: Mapped[Any | None] = mapped_column(JSONB)
    raw: Mapped[Any | None] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


AUDIT_EVENT_COLUMNS: tuple[str, ...] = tuple(
    c.name for c in AuditEvent.__table__.columns if c.name != "id"
)
