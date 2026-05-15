import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse

from database import init_db, SessionLocal
from auth import register_user, login_user
from compliance import compliance_router
from compliance.models import seed_ict_controls

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DORA & MiFID II Compliance-as-Code",
    description=(
        "Agentic RAG system that maps ICT controls to regulatory articles, "
        "produces forensic audit snapshots, and enforces a Semantic PII Kill-Switch."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    try:
        init_db()
        logger.info("Database initialised")
        db = SessionLocal()
        try:
            seed_ict_controls(db)
            logger.info("ICT controls seeded")
        finally:
            db.close()
    except Exception as exc:
        logger.error("Startup failed: %s", exc)
        raise


# ── Static UI ────────────────────────────────────────────────────────────────
# Serve HTML directly (no StaticFiles mount — safe for serverless deployments)

_HTML_PATH = Path(__file__).parent / "static" / "index.html"


@app.get("/", include_in_schema=False)
async def serve_ui():
    if _HTML_PATH.exists():
        return FileResponse(str(_HTML_PATH), media_type="text/html")
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "mock_llm": os.getenv("MOCK_LLM", "false"),
    }


# ── Routes ────────────────────────────────────────────────────────────────────
app.post("/api/auth/register")(register_user)
app.post("/api/auth/login")(login_user)
app.include_router(compliance_router)
