import logging
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from database import init_db, SessionLocal
from auth import register_user, login_user, get_current_user
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


_static = Path(__file__).parent / "static"
if _static.exists():
    app.mount("/static", StaticFiles(directory=str(_static)), name="static")

@app.get("/", include_in_schema=False)
async def serve_ui():
    return FileResponse(str(_static / "index.html"))

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "mock_llm": os.getenv("MOCK_LLM", "false"),
    }


# Auth
app.post("/api/auth/register")(register_user)
app.post("/api/auth/login")(login_user)

# Compliance module
app.include_router(compliance_router)
