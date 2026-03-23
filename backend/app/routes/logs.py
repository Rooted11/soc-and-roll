"""
Log ingestion and analysis routes.
POST /api/logs/ingest  — ingest one or many logs, run anomaly detection
GET  /api/logs         — paginated log list with filters
POST /api/logs/analyze — re-score existing logs
GET  /api/logs/stats   — summary statistics
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..services.database import (
    get_db, Log, Asset, Incident, SeverityEnum, StatusEnum
)
from ..services.anomaly_detection import detector
from ..services.threat_intel import threat_intel
from ..services.playbook import executor
from ..services.claude_service import generate_incident_recommendation

router = APIRouter(prefix="/api/logs", tags=["logs"])


# ── Pydantic schemas ──────────────────────────────────────────────────────

class LogIngest(BaseModel):
    source:     str
    timestamp:  Optional[datetime] = None
    log_level:  Optional[str]      = "info"
    message:    str
    ip_src:     Optional[str]      = None
    ip_dst:     Optional[str]      = None
    user:       Optional[str]      = None
    event_type: Optional[str]      = "unknown"
    raw_data:   Optional[dict]     = {}

class LogBatch(BaseModel):
    logs: List[LogIngest]


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.post("/ingest")
async def ingest_logs(
    payload: LogBatch,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Ingest a batch of logs.
    Each log is:
      1. Saved to the DB
      2. Scored by the Isolation Forest anomaly detector
      3. Correlated against the threat-intel feed
      4. If anomalous → an Incident is created and a playbook is queued
    """
    results = []
    for entry in payload.logs:
        log_dict = entry.model_dump()
        log_dict["timestamp"] = log_dict.get("timestamp") or datetime.utcnow()

        # -- Anomaly scoring --------------------------------------------------
        score_result = detector.score_log(log_dict)

        # -- Asset linkage ----------------------------------------------------
        asset = None
        if entry.ip_src:
            asset = db.query(Asset).filter(Asset.ip_address == entry.ip_src).first()

        # -- Persist log ------------------------------------------------------
        db_log = Log(
            source        = entry.source,
            timestamp     = log_dict["timestamp"],
            log_level     = entry.log_level,
            message       = entry.message,
            raw_data      = entry.raw_data,
            ip_src        = entry.ip_src,
            ip_dst        = entry.ip_dst,
            user          = entry.user,
            event_type    = entry.event_type,
            anomaly_score = score_result["anomaly_score"],
            risk_score    = score_result["risk_score"],
            is_anomalous  = score_result["is_anomalous"],
            explanation   = score_result["explanation"],
            asset_id      = asset.id if asset else None,
        )
        db.add(db_log)
        db.flush()   # get db_log.id before commit

        # -- IOC correlation --------------------------------------------------
        ioc_matches = threat_intel.correlate_log(db, log_dict)

        # -- Auto-create incident when anomalous or IOC matched ---------------
        incident_id = None
        if score_result["is_anomalous"] or ioc_matches:
            sev = detector.classify_severity(score_result["risk_score"])

            # Generate AI recommendation (Claude if key set, else template fallback)
            rec = generate_incident_recommendation(
                incident_title  = f"Anomaly: {entry.event_type} from {entry.ip_src}",
                severity        = sev,
                risk_score      = score_result["risk_score"],
                ioc_matches     = ioc_matches,
                explanation     = score_result["explanation"],
                event_type      = entry.event_type or "",
                affected_assets = [asset.hostname] if asset else [],
            )

            incident = Incident(
                title             = f"[AUTO] {entry.event_type} — {entry.ip_src or 'unknown'} → {entry.ip_dst or 'unknown'}",
                description       = score_result["explanation"],
                severity          = SeverityEnum(sev),
                status            = StatusEnum.open,
                risk_score        = score_result["risk_score"],
                ai_recommendation = rec,
                ioc_matches       = [m["value"] for m in ioc_matches],
                affected_assets   = [asset.hostname] if asset else [],
                trigger_log_id    = db_log.id,
                asset_id          = asset.id if asset else None,
            )
            db.add(incident)
            db.flush()
            db_log.incident = incident
            db.commit()
            incident_id = incident.id

            # Run playbook in background so the HTTP response is not delayed
            background_tasks.add_task(
                _run_playbook_bg, incident.id
            )
        else:
            db.commit()

        results.append({
            "log_id":       db_log.id,
            "is_anomalous": score_result["is_anomalous"],
            "risk_score":   score_result["risk_score"],
            "explanation":  score_result["explanation"],
            "ioc_matches":  len(ioc_matches),
            "incident_id":  incident_id,
        })

    return {"ingested": len(results), "results": results}


@router.get("")
def get_logs(
    source:      Optional[str]  = Query(None),
    anomalous:   Optional[bool] = Query(None),
    min_risk:    float          = Query(0.0),
    skip:        int            = Query(0, ge=0),
    limit:       int            = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """Return paginated, filtered log list."""
    q = db.query(Log)
    if source:
        q = q.filter(Log.source == source)
    if anomalous is not None:
        q = q.filter(Log.is_anomalous == anomalous)
    if min_risk > 0:
        q = q.filter(Log.risk_score >= min_risk)
    total = q.count()
    logs  = q.order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "skip":  skip,
        "limit": limit,
        "logs":  [_log_to_dict(l) for l in logs],
    }


@router.get("/stats")
def log_stats(db: Session = Depends(get_db)):
    """Summary statistics for the dashboard."""
    total     = db.query(Log).count()
    anomalous = db.query(Log).filter(Log.is_anomalous == True).count()
    from sqlalchemy import func
    avg_risk  = db.query(func.avg(Log.risk_score)).scalar() or 0.0
    by_source = (
        db.query(Log.source, func.count(Log.id))
        .group_by(Log.source)
        .all()
    )
    return {
        "total_logs":       total,
        "anomalous_logs":   anomalous,
        "anomaly_rate_pct": round(anomalous / total * 100, 1) if total else 0,
        "avg_risk_score":   round(float(avg_risk), 2),
        "by_source":        {s: c for s, c in by_source},
    }


@router.post("/analyze")
def analyze_logs(
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
):
    """Re-score the most recent N unscored logs."""
    logs = (
        db.query(Log)
        .filter(Log.anomaly_score == 0.0)
        .order_by(Log.timestamp.desc())
        .limit(limit)
        .all()
    )
    updated = 0
    for log in logs:
        d = _log_to_dict(log)
        r = detector.score_log(d)
        log.anomaly_score = r["anomaly_score"]
        log.risk_score    = r["risk_score"]
        log.is_anomalous  = r["is_anomalous"]
        log.explanation   = r["explanation"]
        updated += 1
    db.commit()
    return {"re_scored": updated}


# ── Background task ───────────────────────────────────────────────────────

def _run_playbook_bg(incident_id: int):
    """Execute playbook in background thread (avoids blocking HTTP response)."""
    from ..services.database import SessionLocal
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            executor.execute_for_incident(db, incident)
    finally:
        db.close()


# ── Serialiser ────────────────────────────────────────────────────────────

def _log_to_dict(log: Log) -> dict:
    return {
        "id":            log.id,
        "source":        log.source,
        "timestamp":     log.timestamp.isoformat() if log.timestamp else None,
        "log_level":     log.log_level,
        "message":       log.message,
        "ip_src":        log.ip_src,
        "ip_dst":        log.ip_dst,
        "user":          log.user,
        "event_type":    log.event_type,
        "anomaly_score": log.anomaly_score,
        "risk_score":    log.risk_score,
        "is_anomalous":  log.is_anomalous,
        "explanation":   log.explanation,
        "asset_id":      log.asset_id,
        "incident_id":   log.incident.id if log.incident else None,
    }
