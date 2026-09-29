"""
TRINETRA — SQLAlchemy Declarative Base & Common Mixins

All ORM models inherit from Base.
TimestampMixin provides created_at / updated_at on all tables.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    SQLAlchemy 2.0 declarative base for all TRINETRA models.
    """
    pass


class TimestampMixin:
    """
    Mixin that adds created_at and updated_at timestamp columns.
    Uses server-side defaults so timestamps are always accurate
    regardless of client clock skew.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        index=False,
    )


class UUIDPrimaryKeyMixin:
    """
    Mixin that adds a UUID primary key column named `id`.
    Uses PostgreSQL native UUID type.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
