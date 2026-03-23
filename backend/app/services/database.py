"""
Database service — SQLAlchemy models and session management.
Tables: assets, logs, incidents, alerts, threat_indicators, playbook_actions
"""

import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Enum as SAEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import enum

DATABASE_URL = os.getenv(
    "DATABASE_URL", "sqlite:///./ai_soc.db"
)

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Enums ──────────────────────────────────────────────────────────────────

class SeverityEnum(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"

class StatusEnum(str, enum.Enum):
    open           = "open"
    investigating  = "investigating"
    contained      = "contained"
    resolved       = "resolved"
    false_positive = "false_positive"

class PlaybookStatusEnum(str, enum.Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"


# ── Models ─────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"
    id          = Column(Integer, primary_key=True, index=True)
    hostname    = Column(String(255), unique=True, index=True)
    ip_address  = Column(String(45), index=True)
    asset_type  = Column(String(50))          # server|workstation|network|user
    department  = Column(String(100))
    criticality = Column(String(20), default="medium")
    is_isolated = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    logs      = relationship("Log",      back_populates="asset")
    incidents = relationship("Incident", back_populates="asset")


class Log(Base):
    __tablename__ = "logs"
    id            = Column(Integer, primary_key=True, index=True)
    source        = Column(String(100), index=True)   # syslog|firewall|auth|endpoint
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    log_level     = Column(String(20))
    message       = Column(Text)
    raw_data      = Column(JSON)
    ip_src        = Column(String(45), index=True)
    ip_dst        = Column(String(45))
    user          = Column(String(150))
    event_type    = Column(String(100))
    anomaly_score = Column(Float, default=0.0)
    risk_score    = Column(Float, default=0.0)
    is_anomalous  = Column(Boolean, default=False)
    explanation   = Column(Text)
    asset_id      = Column(Integer, ForeignKey("assets.id"), nullable=True)

    asset    = relationship("Asset",    back_populates="logs")
    incident = relationship("Incident", back_populates="trigger_log", uselist=False)


class Incident(Base):
    __tablename__ = "incidents"
    id                = Column(Integer, primary_key=True, index=True)
    title             = Column(String(300))
    description       = Column(Text)
    severity          = Column(SAEnum(SeverityEnum), default=SeverityEnum.medium)
    status            = Column(SAEnum(StatusEnum),   default=StatusEnum.open)
    risk_score        = Column(Float, default=0.0)
    ai_recommendation = Column(Text)
    ioc_matches       = Column(JSON, default=list)
    affected_assets   = Column(JSON, default=list)
    created_at        = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at       = Column(DateTime, nullable=True)
    trigger_log_id    = Column(Integer, ForeignKey("logs.id"), nullable=True)
    asset_id          = Column(Integer, ForeignKey("assets.id"), nullable=True)

    trigger_log      = relationship("Log",            back_populates="incident")
    asset            = relationship("Asset",          back_populates="incidents")
    alerts           = relationship("Alert",          back_populates="incident")
    playbook_actions = relationship("PlaybookAction", back_populates="incident")


class Alert(Base):
    __tablename__ = "alerts"
    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    channel     = Column(String(50))   # email|slack|pagerduty
    recipient   = Column(String(255))
    message     = Column(Text)
    sent_at     = Column(DateTime, default=datetime.utcnow)
    delivered   = Column(Boolean, default=True)

    incident = relationship("Incident", back_populates="alerts")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id          = Column(Integer, primary_key=True, index=True)
    ioc_type    = Column(String(50), index=True)   # ip|domain|hash|url|email
    value       = Column(String(500), index=True)
    threat_type = Column(String(100))
    severity    = Column(String(20))
    confidence  = Column(Float, default=0.5)
    feed_source = Column(String(100))
    description = Column(Text)
    tags        = Column(JSON, default=list)
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)
    is_active   = Column(Boolean, default=True)


class PlaybookAction(Base):
    __tablename__ = "playbook_actions"
    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    playbook    = Column(String(100))
    action      = Column(String(200))
    target      = Column(String(200))
    status      = Column(SAEnum(PlaybookStatusEnum), default=PlaybookStatusEnum.completed)
    result      = Column(Text)
    executed_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="playbook_actions")


# ── Helpers ────────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and seed demo assets."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Asset).count() == 0:
            db.add_all([
                Asset(hostname="web-server-01",  ip_address="10.0.1.10",   asset_type="server",      department="Engineering",  criticality="high"),
                Asset(hostname="db-server-01",   ip_address="10.0.1.20",   asset_type="server",      department="Engineering",  criticality="critical"),
                Asset(hostname="workstation-42", ip_address="10.0.2.42",   asset_type="workstation", department="Finance",      criticality="medium"),
                Asset(hostname="vpn-gateway",    ip_address="203.0.113.1", asset_type="network",     department="IT",           criticality="high"),
                Asset(hostname="mail-server-01", ip_address="10.0.1.30",   asset_type="server",      department="IT",           criticality="high"),
                Asset(hostname="dc-server-01",   ip_address="10.0.1.5",    asset_type="server",      department="IT",           criticality="critical"),
            ])
            db.commit()
    finally:
        db.close()
