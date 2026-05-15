from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ICTControlRecord:
    id: str
    name: str
    description: str
    owner: str
    status: str          # "implemented" | "partial" | "gap"
    version: str
    last_reviewed: str   # ISO date
    dora_articles: List[str]
    mifid_articles: List[str]
    control_type: str    # "preventive" | "detective" | "corrective"


CONTROLS_SEED: List[dict] = [
    {
        "id": "ICT-001",
        "name": "Incident Classification & Reporting Framework",
        "description": (
            "Defines severity tiers (P1–P4) for ICT incidents, mandatory escalation "
            "paths, and regulatory notification timelines per DORA Art.17. Includes "
            "runbooks for major incident response and post-incident review templates."
        ),
        "owner": "CISO Office",
        "status": "implemented",
        "version": "2.1",
        "last_reviewed": "2025-11-30",
        "dora_articles": ["Art.17"],
        "mifid_articles": ["Art.16"],
        "control_type": "detective",
    },
    {
        "id": "ICT-002",
        "name": "Third-Party ICT Risk Assessment",
        "description": (
            "Risk scoring framework for critical ICT third-party providers. Covers "
            "due-diligence questionnaires, on-site audit rights, exit strategy "
            "requirements, and concentration-risk monitoring per DORA Art.7."
        ),
        "owner": "Vendor Risk Team",
        "status": "partial",
        "version": "1.3",
        "last_reviewed": "2025-09-15",
        "dora_articles": ["Art.7"],
        "mifid_articles": ["Art.16"],
        "control_type": "preventive",
    },
    {
        "id": "ICT-003",
        "name": "ICT Risk Management Framework",
        "description": (
            "Enterprise-wide ICT risk governance framework encompassing risk appetite "
            "statement, risk register, annual review cadence, and board-level reporting. "
            "Aligned to ISO 27001 and DORA Art.5 requirements."
        ),
        "owner": "CRO / Technology Risk",
        "status": "implemented",
        "version": "3.0",
        "last_reviewed": "2026-01-10",
        "dora_articles": ["Art.5"],
        "mifid_articles": ["Art.16"],
        "control_type": "preventive",
    },
    {
        "id": "ICT-004",
        "name": "ICT Systems Resilience & Availability",
        "description": (
            "Availability SLAs (99.95% uptime) for critical systems, redundancy "
            "architecture requirements, capacity planning processes, and performance "
            "monitoring thresholds per DORA Art.6."
        ),
        "owner": "Infrastructure Engineering",
        "status": "partial",
        "version": "1.8",
        "last_reviewed": "2025-10-22",
        "dora_articles": ["Art.6"],
        "mifid_articles": [],
        "control_type": "preventive",
    },
    {
        "id": "ICT-005",
        "name": "Data Protection & Encryption Controls",
        "description": (
            "Encryption standards (AES-256 at rest, TLS 1.3 in transit), key management "
            "procedures, data classification policy, and privacy-by-design requirements "
            "per DORA Art.9 and GDPR obligations."
        ),
        "owner": "Data Protection Officer",
        "status": "implemented",
        "version": "2.4",
        "last_reviewed": "2025-12-05",
        "dora_articles": ["Art.9"],
        "mifid_articles": ["Art.16"],
        "control_type": "preventive",
    },
    {
        "id": "ICT-006",
        "name": "Business Continuity & Disaster Recovery",
        "description": (
            "BCP/DR plans covering RTO ≤4h and RPO ≤1h for critical systems. "
            "Annual DR test exercises required. Currently a gap: last test exercise "
            "found recovery time exceeded targets for two legacy trading platforms."
        ),
        "owner": "Business Continuity Management",
        "status": "gap",
        "version": "1.1",
        "last_reviewed": "2025-08-01",
        "dora_articles": ["Art.11"],
        "mifid_articles": ["Art.16"],
        "control_type": "corrective",
    },
    {
        "id": "ICT-007",
        "name": "Network Segmentation & Access Control",
        "description": (
            "Zero-trust network architecture with micro-segmentation, privileged access "
            "management (PAM), MFA enforcement for all privileged accounts, and quarterly "
            "access reviews. Maps to DORA Art.9 protection requirements."
        ),
        "owner": "Network Security Team",
        "status": "implemented",
        "version": "2.2",
        "last_reviewed": "2026-02-14",
        "dora_articles": ["Art.9"],
        "mifid_articles": ["Art.16"],
        "control_type": "preventive",
    },
    {
        "id": "ICT-008",
        "name": "Vulnerability Management & Patch Cycle",
        "description": (
            "Monthly vulnerability scans, risk-tiered patch SLAs (Critical: 72h, High: 14d, "
            "Medium: 30d), and exception management process. Partial status: patch SLAs "
            "met for cloud assets but two on-prem systems have outstanding Critical findings."
        ),
        "owner": "Cyber Defence Centre",
        "status": "partial",
        "version": "1.6",
        "last_reviewed": "2025-11-01",
        "dora_articles": ["Art.6", "Art.9"],
        "mifid_articles": ["Art.16"],
        "control_type": "detective",
    },
    {
        "id": "ICT-009",
        "name": "ICT Audit Logging & Monitoring",
        "description": (
            "Centralised SIEM with 12-month log retention, real-time alerting on "
            "anomalous access patterns, and automated threat intelligence feeds. "
            "Supports DORA Art.5 risk monitoring and Art.17 incident detection."
        ),
        "owner": "Security Operations Centre",
        "status": "implemented",
        "version": "3.1",
        "last_reviewed": "2026-01-28",
        "dora_articles": ["Art.5", "Art.17"],
        "mifid_articles": ["Art.16"],
        "control_type": "detective",
    },
    {
        "id": "ICT-010",
        "name": "Concentration Risk — Critical Third Parties",
        "description": (
            "Monitoring and reporting framework for ICT concentration risk where a single "
            "provider supports multiple critical functions. Currently a gap: no formal "
            "concentration-risk threshold defined or breach escalation procedure documented."
        ),
        "owner": "Vendor Risk Team",
        "status": "gap",
        "version": "0.9",
        "last_reviewed": "2025-07-15",
        "dora_articles": ["Art.7"],
        "mifid_articles": ["Art.16"],
        "control_type": "preventive",
    },
]

CONTROLS_INDEX: List[ICTControlRecord] = [
    ICTControlRecord(**c) for c in CONTROLS_SEED
]


def query_controls(
    article_id: Optional[str] = None,
    control_type: Optional[str] = None,
    status: Optional[str] = None,
) -> List[ICTControlRecord]:
    results = CONTROLS_INDEX
    if article_id:
        normalized = article_id.strip()
        results = [
            c for c in results
            if normalized in c.dora_articles or normalized in c.mifid_articles
        ]
    if control_type:
        results = [c for c in results if c.control_type == control_type]
    if status:
        results = [c for c in results if c.status == status]
    return results


def get_control_by_id(control_id: str) -> Optional[ICTControlRecord]:
    for c in CONTROLS_INDEX:
        if c.id == control_id:
            return c
    return None


def get_all_controls() -> List[ICTControlRecord]:
    return CONTROLS_INDEX
