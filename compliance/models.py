from datetime import datetime

from sqlalchemy import Column, Float, Index, Integer, JSON, String, Text, DateTime
from sqlalchemy.orm import Session

from database import Base


class ComplianceSnapshot(Base):
    """Immutable forensic audit record. Written once; the signature locks the content."""
    __tablename__ = "compliance_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), unique=True, index=True, nullable=False)
    user_id = Column(String(100), nullable=False, index=True)
    query = Column(Text, nullable=False)
    regulation = Column(String(20), nullable=False)
    result_json = Column(JSON, nullable=False)
    compliance_score = Column(Float, nullable=True)
    agent_steps = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    signature = Column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_snapshot_user_created", "user_id", "created_at"),
    )


class ICTControl(Base):
    """ICT security control. Seeded at startup from controls_db.CONTROLS_SEED."""
    __tablename__ = "ict_controls"

    id = Column(String(20), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    owner = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False)
    version = Column(String(10), nullable=False)
    last_reviewed = Column(String(20), nullable=False)
    dora_articles = Column(JSON, nullable=True)
    mifid_articles = Column(JSON, nullable=True)
    control_type = Column(String(50), nullable=False)


def seed_ict_controls(db: Session) -> None:
    """Idempotent seed — only inserts when the table is empty."""
    from compliance.controls_db import CONTROLS_SEED

    if db.query(ICTControl).count() == 0:
        for c in CONTROLS_SEED:
            db.add(ICTControl(**c))
        db.commit()
