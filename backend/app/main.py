"""
FastAPI application entry point for the AI-Powered SOC backend.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.database import init_db
from app.services.threat_intel import threat_intel
from app.services.database import SessionLocal
from app.routes.logs import router as logs_router
from app.routes.incidents import router as incidents_router
from app.routes.ai import router as ai_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle handler."""
    logger.info("Initialising database tables and seed data...")
    init_db()

    logger.info("Loading threat intelligence feeds...")
    db = SessionLocal()
    try:
        threat_intel.load_from_file(db)
        threat_intel.fetch_live_feed(db)
    finally:
        db.close()

    logger.info("AI-SOC backend ready.")
    yield
    logger.info("AI-SOC backend shutting down.")


app = FastAPI(
    title="AI-Powered Security Operations Center",
    description=(
        "Automated incident response, anomaly detection, threat intelligence "
        "correlation, and decision-support for SOC analysts."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the React dev server (port 3000) and any other origin in dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs_router)
app.include_router(incidents_router)
app.include_router(ai_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-soc-backend"}


@app.get("/")
def root():
    return {
        "message": "AI-SOC API is running. Visit /docs for the interactive API explorer."
    }
