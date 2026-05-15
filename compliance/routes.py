from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from compliance.compliance_agent import ComplianceAgent
from compliance.controls_db import get_all_controls, query_controls
from compliance.models import ComplianceSnapshot
from compliance.pii_guard import ClearanceLevel, PIIGuard, PIIKillSwitchException

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class ComplianceAnalyzeRequest(BaseModel):
    query: str = Field(
        ..., min_length=10, max_length=1000,
        example="Map our ICT controls to DORA Article 9 and identify gaps",
    )
    regulation: str = Field("DORA", pattern="^(DORA|MIFID_II|BOTH)$")
    clearance_level: str = Field("ANALYST", pattern="^(ANALYST|COMPLIANCE_OFFICER|DPO)$")


class PIIScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    clearance_level: str = Field("ANALYST", pattern="^(ANALYST|COMPLIANCE_OFFICER|DPO)$")


@router.post("/analyze", summary="Run agentic compliance analysis (ReAct loop)")
async def analyze_compliance(
    request: ComplianceAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Executes a multi-step ReAct loop:
    1. Retrieves DORA / MiFID II article requirements via MCP tools
    2. Queries the internal ICT controls database
    3. Passes each result through the PII Semantic Kill-Switch
    4. Produces gap analysis and compliance score
    5. Seals result as an immutable SHA-256 signed ForensicSnapshot
    """
    agent = ComplianceAgent(user_clearance=ClearanceLevel(request.clearance_level))
    try:
        result = await agent.run(
            query=request.query,
            regulation=request.regulation,
            user_id=current_user.user_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.get("/snapshot/{snapshot_id}", summary="Retrieve a forensic audit snapshot")
async def get_snapshot(
    snapshot_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Returns the stored snapshot and verifies its SHA-256 integrity signature."""
    import hashlib, json

    record = (
        db.query(ComplianceSnapshot)
        .filter(
            ComplianceSnapshot.snapshot_id == snapshot_id,
            ComplianceSnapshot.user_id == current_user.user_id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    canonical = json.dumps({
        "snapshot_id": record.snapshot_id,
        "timestamp": record.created_at.isoformat(),
        "query": record.query,
        "regulation": record.regulation,
        "user_id": record.user_id,
        "agent_steps": record.agent_steps or [],
        "matched_controls": record.result_json.get("matched_controls", []),
        "gap_analysis": record.result_json.get("gap_analysis", []),
        "compliance_score": record.compliance_score,
        "evidence": [],
    }, sort_keys=True, separators=(",", ":"), default=str)
    integrity_ok = hashlib.sha256(canonical.encode()).hexdigest() == record.signature

    return {
        "snapshot_id": record.snapshot_id,
        "query": record.query,
        "regulation": record.regulation,
        "compliance_score": record.compliance_score,
        "created_at": record.created_at.isoformat(),
        "agent_steps": record.agent_steps,
        "result": record.result_json,
        "auditor_signature": record.signature,
        "integrity_verified": integrity_ok,
    }


@router.get("/controls", summary="List ICT controls with optional filters")
async def list_controls(
    article_id: Optional[str] = None,
    control_type: Optional[str] = None,
    status: Optional[str] = None,
    current_user=Depends(get_current_user),
):
    """Returns ICT controls from the in-memory index. No database round-trip required."""
    controls = (
        query_controls(article_id=article_id, control_type=control_type, status=status)
        if (article_id or control_type or status)
        else get_all_controls()
    )
    return {"total": len(controls), "controls": [c.__dict__ for c in controls]}


@router.post("/pii-scan", summary="Scan text for PII (Semantic Kill-Switch demo)")
async def scan_for_pii(
    request: PIIScanRequest,
    current_user=Depends(get_current_user),
):
    """
    Demonstrates the Semantic Kill-Switch in isolation.
    Scans for emails, IBANs, phone numbers, national IDs, account numbers, and names.
    Enforces clearance-level access control: ANALYST is blocked on HIGH risk PII,
    COMPLIANCE_OFFICER on HIGH only, DPO receives anonymized text for all levels.
    """
    guard = PIIGuard()
    result = guard.scan(request.text)
    blocked, anonymized = False, result.anonymized_text

    if result.found:
        try:
            anonymized, _ = guard.enforce_kill_switch(
                request.text, ClearanceLevel(request.clearance_level)
            )
        except PIIKillSwitchException:
            blocked, anonymized = True, None

    return {
        "pii_found": result.found,
        "risk_level": result.risk_level.value,
        "entity_count": len(result.entities),
        "entity_types": list({e.pii_type.value for e in result.entities}),
        "access_blocked": blocked,
        "anonymized_text": anonymized if not blocked else None,
        "kill_switch_message": (
            f"Access blocked: {result.risk_level.value} risk PII detected. "
            "Escalate to DPO for access."
        ) if blocked else None,
    }
