"""Add query history persistence.

Revision ID: 2b7d9a4c1e63
Revises: 8f4c2a1d6b30
Create Date: 2026-10-11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2b7d9a4c1e63"
down_revision: Union[str, None] = "8f4c2a1d6b30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "query_history",
        sa.Column("shift_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("query_text", sa.Text(), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["shift_id"], ["shifts.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_query_history_shift_id", "query_history", ["shift_id"])
    op.create_index("ix_query_history_user_id", "query_history", ["user_id"])
    op.create_index(
        "ix_query_history_shift_executed",
        "query_history",
        ["shift_id", "executed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_query_history_shift_executed", table_name="query_history")
    op.drop_index("ix_query_history_user_id", table_name="query_history")
    op.drop_index("ix_query_history_shift_id", table_name="query_history")
    op.drop_table("query_history")
