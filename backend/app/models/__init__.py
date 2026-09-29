"""
TRINETRA — Database Models
Core models representing emails, identities, intelligence signals, graph entities, incidents, and feedback.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


# ==================================================
# Enums
# ==================================================

class EmailState(str, enum.Enum):
    RECEIVED = "RECEIVED"
    PARSING = "PARSING"
    ANALYZING = "ANALYZING"
    ANALYZED = "ANALYZED"
    ACTION_PENDING = "ACTION_PENDING"
    ACTIONED = "ACTIONED"
    FAILED = "FAILED"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    QUARANTINE = "QUARANTINE"


class FeedbackClassification(str, enum.Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


# ==================================================
# Models
# ==================================================

class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """System user or SOC analyst."""
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst", nullable=False)

    gmail_accounts: Mapped[List["GmailAccount"]] = relationship("GmailAccount", back_populates="user", cascade="all, delete-orphan")
    feedbacks: Mapped[List["Feedback"]] = relationship("Feedback", back_populates="analyst")
    assigned_incidents: Mapped[List["Incident"]] = relationship("Incident", back_populates="assignee")


class GmailAccount(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Connected Gmail account monitored by TRINETRA."""
    __tablename__ = "gmail_accounts"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email_address: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    history_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    watch_expiration: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    # Secure storage for token information
    token_info: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="gmail_accounts")
    emails: Mapped[List["Email"]] = relationship("Email", back_populates="gmail_account", cascade="all, delete-orphan")


class Domain(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Domain intelligence and reputation registry."""
    __tablename__ = "domains"

    domain_name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    reputation_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    is_lookalike: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    target_brand: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    whois_data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    urls: Mapped[List["EmailUrl"]] = relationship("EmailUrl", back_populates="domain_record")


class Email(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Ingested email records and core analysis states."""
    __tablename__ = "emails"

    gmail_account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("gmail_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    message_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    thread_id: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    sender: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    sender_domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    subject: Mapped[str] = mapped_column(Text, default="", nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # State tracking
    state: Mapped[EmailState] = mapped_column(
        Enum(EmailState, name="email_state_enum", native_enum=False),
        default=EmailState.RECEIVED,
        nullable=False,
        index=True,
    )

    # Technical headers / Authentication
    spf_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    dkim_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    dmarc_result: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    raw_headers: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    gmail_account: Mapped["GmailAccount"] = relationship("GmailAccount", back_populates="emails")
    urls: Mapped[List["EmailUrl"]] = relationship("EmailUrl", back_populates="email", cascade="all, delete-orphan")
    detection: Mapped[Optional["Detection"]] = relationship("Detection", back_populates="email", uselist=False, cascade="all, delete-orphan")
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="email", uselist=False)


class EmailUrl(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """URLs extracted from ingested emails."""
    __tablename__ = "email_urls"

    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, index=True)
    raw_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, index=True, nullable=False)
    url_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    email: Mapped["Email"] = relationship("Email", back_populates="urls")
    domain_record: Mapped[Optional["Domain"]] = relationship("Domain", back_populates="urls")


class Detection(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Detection results produced by the Multi-Signal Risk Engine."""
    __tablename__ = "detections"

    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    
    # Sub-layer scores (0.0 to 1.0)
    content_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    url_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    identity_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threat_intel_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    graph_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Risk Engine final outputs
    final_risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity_enum", native_enum=False),
        default=Severity.LOW,
        nullable=False,
        index=True,
    )
    decision: Mapped[Decision] = mapped_column(
        Enum(Decision, name="decision_enum", native_enum=False),
        default=Decision.ALLOW,
        nullable=False,
        index=True,
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    
    # Explainability & Evidence
    explanation_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    recommended_action: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    email: Mapped["Email"] = relationship("Email", back_populates="detection")
    risk_signals: Mapped[List["RiskSignal"]] = relationship("RiskSignal", back_populates="detection", cascade="all, delete-orphan")
    feedback: Mapped[Optional["Feedback"]] = relationship("Feedback", back_populates="detection", uselist=False, cascade="all, delete-orphan")


class RiskSignal(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Granular signals captured by each intelligence layer."""
    __tablename__ = "risk_signals"

    detection_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detections.id", ondelete="CASCADE"), nullable=False, index=True)
    layer: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    signal_type: Mapped[str] = mapped_column(String(100), nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    detection: Mapped["Detection"] = relationship("Detection", back_populates="risk_signals")


class ThreatIndicator(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Threat intelligence IOC records (CERT-In, VT, Safe Browsing, Local DB)."""
    __tablename__ = "threat_indicators"

    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True) # domain, ip, url, hash, sender
    indicator_value: Mapped[str] = mapped_column(String(500), unique=True, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="indicator_severity_enum", native_enum=False),
        default=Severity.MEDIUM,
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class GraphEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Nodes representing entities in the Graph Intelligence layer."""
    __tablename__ = "graph_entities"

    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True) # sender, domain, ip, url, recipient
    identifier: Mapped[str] = mapped_column(String(500), unique=True, index=True, nullable=False)
    properties: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    outgoing_relationships: Mapped[List["GraphRelationship"]] = relationship(
        "GraphRelationship",
        foreign_keys="GraphRelationship.source_entity_id",
        back_populates="source_entity",
        cascade="all, delete-orphan",
    )
    incoming_relationships: Mapped[List["GraphRelationship"]] = relationship(
        "GraphRelationship",
        foreign_keys="GraphRelationship.target_entity_id",
        back_populates="target_entity",
        cascade="all, delete-orphan",
    )


class GraphRelationship(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Edges linking entities in the Graph Intelligence layer."""
    __tablename__ = "graph_relationships"

    source_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_entities.id", ondelete="CASCADE"), nullable=False, index=True)
    target_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_entities.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    properties: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    source_entity: Mapped["GraphEntity"] = relationship("GraphEntity", foreign_keys=[source_entity_id], back_populates="outgoing_relationships")
    target_entity: Mapped["GraphEntity"] = relationship("GraphEntity", foreign_keys=[target_entity_id], back_populates="incoming_relationships")


class Feedback(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Human-in-the-loop analyst feedback on detections."""
    __tablename__ = "feedbacks"

    detection_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detections.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    analyst_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    classification: Mapped[FeedbackClassification] = mapped_column(
        Enum(FeedbackClassification, name="feedback_classification_enum", native_enum=False),
        nullable=False,
    )
    comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    detection: Mapped["Detection"] = relationship("Detection", back_populates="feedback")
    analyst: Mapped["User"] = relationship("User", back_populates="feedbacks")


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """SOC security incidents tracked from flagged emails."""
    __tablename__ = "incidents"

    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="RESTRICT"), unique=True, nullable=False, index=True)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status_enum", native_enum=False),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="incident_severity_enum", native_enum=False),
        default=Severity.MEDIUM,
        nullable=False,
    )
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    email: Mapped["Email"] = relationship("Email", back_populates="incident")
    assignee: Mapped[Optional["User"]] = relationship("User", back_populates="assigned_incidents")
