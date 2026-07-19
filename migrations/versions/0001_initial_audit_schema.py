"""Initial audit schema: audit_events, budget_alert_state, scim_users, scim_groups.

Revision ID: 0001
Revises:
Create Date: 2026-07-19
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text()),
        sa.Column("user_id", sa.Text()),
        sa.Column("user_email", sa.Text()),
        sa.Column("team_id", sa.Text()),
        sa.Column("idp_roles", postgresql.JSONB()),
        sa.Column("model_requested", sa.Text()),
        sa.Column("model_actual", sa.Text()),
        sa.Column("provider", sa.Text()),
        sa.Column("route", sa.Text()),
        sa.Column("client_ip", postgresql.INET()),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error_class", sa.Text()),
        sa.Column("http_status", sa.Integer()),
        sa.Column("prompt_tokens", sa.Integer()),
        sa.Column("completion_tokens", sa.Integer()),
        sa.Column("total_tokens", sa.Integer()),
        sa.Column("cost_usd", sa.Numeric(12, 6)),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("prompt_sha256", sa.Text()),
        sa.Column("response_sha256", sa.Text()),
        sa.Column("prompt_body", sa.Text()),
        sa.Column("response_body", sa.Text()),
        sa.Column("guardrail_info", postgresql.JSONB()),
        sa.Column("extra", postgresql.JSONB()),
    )
    op.create_index("ix_audit_events_ts", "audit_events", ["ts"])
    op.create_index("ix_audit_events_user_ts", "audit_events", ["user_id", "ts"])
    op.create_index("ix_audit_events_team_ts", "audit_events", ["team_id", "ts"])
    op.create_index("ix_audit_events_type_ts", "audit_events", ["event_type", "ts"])

    op.create_table(
        "budget_alert_state",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("month", sa.Text(), nullable=False),
        sa.Column("threshold_pct", sa.Integer(), nullable=False),
        sa.Column("fired_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ux_budget_alert_once",
        "budget_alert_state",
        ["subject", "month", "threshold_pct"],
        unique=True,
    )

    op.create_table(
        "scim_users",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("external_id", sa.Text()),
        sa.Column("user_name", sa.Text(), nullable=False),
        sa.Column("email", sa.Text()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("raw", postgresql.JSONB()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scim_groups",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("members", postgresql.JSONB()),
        sa.Column("raw", postgresql.JSONB()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Tamper resistance (§6.5): the app role is INSERT-only on audit_events;
    # auditors read via a separate role. Roles are created by deploy tooling:
    #   GRANT INSERT ON audit_events TO litellm_ext_app;
    #   GRANT SELECT ON audit_events TO litellm_ext_auditor;


def downgrade() -> None:
    op.drop_table("scim_groups")
    op.drop_table("scim_users")
    op.drop_index("ux_budget_alert_once", table_name="budget_alert_state")
    op.drop_table("budget_alert_state")
    for index in (
        "ix_audit_events_type_ts",
        "ix_audit_events_team_ts",
        "ix_audit_events_user_ts",
        "ix_audit_events_ts",
    ):
        op.drop_index(index, table_name="audit_events")
    op.drop_table("audit_events")
