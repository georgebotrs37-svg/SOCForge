"""Add generated shift template and duration columns.

Revision ID: 8f4c2a1d6b30
Revises: 2718c29c8cc9
Create Date: 2026-10-11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8f4c2a1d6b30"
down_revision: Union[str, None] = "2718c29c8cc9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "shifts",
        sa.Column("template", sa.String(length=40), nullable=False, server_default="brute_force"),
    )
    op.add_column(
        "shifts",
        sa.Column("duration_minutes", sa.Integer(), nullable=False, server_default="30"),
    )


def downgrade() -> None:
    op.drop_column("shifts", "duration_minutes")
    op.drop_column("shifts", "template")
