import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceItem:
    source_id: str        # e.g. "DORA-Art.9" or "ICT-005"
    source_type: str      # "regulatory_article" | "ict_control" | "agent_reasoning"
    document: str         # relevant text excerpt
    version: str          # article version or control version
    rationale: str        # why this evidence supports the compliance claim


@dataclass
class ReActStep:
    step_number: int
    thought: str
    action: str
    action_input: Dict[str, Any]
    observation: str
    timestamp: str        # ISO datetime


@dataclass
class ForensicSnapshot:
    snapshot_id: str
    timestamp: str
    query: str
    regulation: str
    user_id: str
    agent_steps: List[ReActStep]
    matched_controls: List[dict]
    gap_analysis: List[dict]
    compliance_score: float
    evidence: List[EvidenceItem]
    auditor_signature: str   # SHA-256 hex; empty string before signing

    def canonical_content(self) -> str:
        """Deterministic JSON for signing — excludes auditor_signature."""
        data = {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "query": self.query,
            "regulation": self.regulation,
            "user_id": self.user_id,
            "agent_steps": [asdict(s) for s in self.agent_steps],
            "matched_controls": self.matched_controls,
            "gap_analysis": self.gap_analysis,
            "compliance_score": self.compliance_score,
            "evidence": [asdict(e) for e in self.evidence],
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def generate_snapshot(
    query: str,
    regulation: str,
    user_id: str,
    agent_steps: List[ReActStep],
    matched_controls: List[dict],
    gap_analysis: List[dict],
    compliance_score: float,
    evidence: List[EvidenceItem],
) -> ForensicSnapshot:
    """Factory: creates snapshot and seals it with a SHA-256 signature."""
    snap = ForensicSnapshot(
        snapshot_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        query=query,
        regulation=regulation,
        user_id=user_id,
        agent_steps=agent_steps,
        matched_controls=matched_controls,
        gap_analysis=gap_analysis,
        compliance_score=compliance_score,
        evidence=evidence,
        auditor_signature="",
    )
    snap.auditor_signature = hashlib.sha256(
        snap.canonical_content().encode("utf-8")
    ).hexdigest()
    return snap


def verify_snapshot_integrity(snapshot: ForensicSnapshot) -> bool:
    """Re-computes SHA-256 and compares to stored signature."""
    stored = snapshot.auditor_signature
    snapshot.auditor_signature = ""
    recomputed = hashlib.sha256(
        snapshot.canonical_content().encode("utf-8")
    ).hexdigest()
    snapshot.auditor_signature = stored
    return recomputed == stored


def export_snapshot_json(snapshot: ForensicSnapshot) -> dict:
    """Returns full snapshot as JSON-serialisable dict with integrity flag."""
    base = json.loads(snapshot.canonical_content())
    return {
        **base,
        "auditor_signature": snapshot.auditor_signature,
        "integrity_verified": verify_snapshot_integrity(snapshot),
    }
