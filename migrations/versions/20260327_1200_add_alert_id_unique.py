"""add alert_id unique constraint to alerts

Revision ID: 20260327_1200
Revises:
Create Date: 2026-03-27 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = "20260327_1200"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    # Fresh database bootstrap path: create current schema and mark this revision as applied.
    if not inspector.has_table("alerts"):
        from db.session import Base
        from db import models  # noqa: F401

        Base.metadata.create_all(bind=bind)
        return

    # 1) Add nullable column first so we can backfill safely.
    columns = {col["name"] for col in inspector.get_columns("alerts")}
    if "alert_id" not in columns:
        op.add_column("alerts", sa.Column("alert_id", sa.String(length=64), nullable=True))

    # 2) Backfill from payload->alert_id where available; otherwise derive deterministic legacy id.
    # 3) Resolve duplicates before uniqueness by suffixing with row id on collisions.
        op.execute(
            """
            WITH ranked AS (
              SELECT
                id,
                COALESCE(NULLIF(payload->>'alert_id', ''), 'LEGACY-' || id::text) AS base_id,
                ROW_NUMBER() OVER (
                  PARTITION BY COALESCE(NULLIF(payload->>'alert_id', ''), 'LEGACY-' || id::text)
                  ORDER BY id
                ) AS rn
              FROM alerts
            )
            UPDATE alerts a
            SET alert_id = CASE
              WHEN ranked.rn = 1 THEN ranked.base_id
              ELSE ranked.base_id || '-' || a.id::text
            END
            FROM ranked
            WHERE a.id = ranked.id
            """
        )

    # 4) Enforce NOT NULL + uniqueness + index for idempotent worker inserts.
    op.alter_column("alerts", "alert_id", existing_type=sa.String(length=64), nullable=False)

    unique_constraints = {uc["name"] for uc in inspector.get_unique_constraints("alerts")}
    if "uq_alerts_alert_id" not in unique_constraints:
        op.create_unique_constraint("uq_alerts_alert_id", "alerts", ["alert_id"])

    indexes = {idx["name"] for idx in inspector.get_indexes("alerts")}
    if "ix_alerts_alert_id" not in indexes:
        op.create_index("ix_alerts_alert_id", "alerts", ["alert_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_alerts_alert_id", table_name="alerts")
    op.drop_constraint("uq_alerts_alert_id", "alerts", type_="unique")
    op.drop_column("alerts", "alert_id")
