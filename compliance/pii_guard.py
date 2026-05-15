"""
Semantic Kill-Switch — PII detection and clearance-based enforcement.

Intercepts retrieval results BEFORE they are appended to the LLM context window.
Two-layer detection: fast regex first, heuristic name detection second.
"""
import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class PIIType(str, Enum):
    NAME = "NAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    NATIONAL_ID = "NATIONAL_ID"
    IBAN = "IBAN"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ClearanceLevel(str, Enum):
    ANALYST = "ANALYST"
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    DPO = "DPO"


@dataclass
class PIIEntity:
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float


@dataclass
class PIIDetectionResult:
    found: bool
    entities: List[PIIEntity]
    risk_level: RiskLevel
    anonymized_text: Optional[str] = None


class PIIKillSwitchException(Exception):
    def __init__(self, risk_level: RiskLevel, entity_types: List[PIIType]) -> None:
        self.risk_level = risk_level
        self.entity_types = entity_types
        types_str = ", ".join(t.value for t in entity_types)
        super().__init__(
            f"Retrieval blocked: {risk_level.value} PII detected ({types_str}). "
            f"Insufficient clearance level."
        )


_RISK_MAP: Dict[PIIType, RiskLevel] = {
    PIIType.IBAN: RiskLevel.HIGH,
    PIIType.ACCOUNT_NUMBER: RiskLevel.HIGH,
    PIIType.NATIONAL_ID: RiskLevel.HIGH,
    PIIType.EMAIL: RiskLevel.MEDIUM,
    PIIType.PHONE: RiskLevel.MEDIUM,
    PIIType.NAME: RiskLevel.LOW,
}
_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
_CLEARANCE_ALLOWED: Dict[ClearanceLevel, Set[RiskLevel]] = {
    ClearanceLevel.ANALYST: set(),
    ClearanceLevel.COMPLIANCE_OFFICER: {RiskLevel.LOW, RiskLevel.MEDIUM},
    ClearanceLevel.DPO: {RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH},
}
_REDACTION_TOKENS: Dict[PIIType, str] = {
    PIIType.NAME: "[NAME_REDACTED]",
    PIIType.EMAIL: "[EMAIL_REDACTED]",
    PIIType.PHONE: "[PHONE_REDACTED]",
    PIIType.NATIONAL_ID: "[NATIONAL_ID_REDACTED]",
    PIIType.IBAN: "[IBAN_REDACTED]",
    PIIType.ACCOUNT_NUMBER: "[ACCOUNT_REDACTED]",
}
_PATTERNS: Dict[PIIType, re.Pattern] = {
    PIIType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    PIIType.IBAN: re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b"),
    PIIType.NATIONAL_ID: re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\d{2}[\/\-]\d{2}[\/\-]\d{4})\b"),
    PIIType.PHONE: re.compile(r"(?<!\d)(?:\+?\d[\s\-.]?){7,14}\d(?!\d)"),
    PIIType.ACCOUNT_NUMBER: re.compile(r"\b\d{8,18}\b"),
}
_NAME_TRIGGER_RE = re.compile(
    r"\b(?:name|contact|client|customer|employee|advisor|owner|officer)\s*:",
    re.IGNORECASE,
)
_PRIORITY = {
    PIIType.IBAN: 4, PIIType.NATIONAL_ID: 3, PIIType.ACCOUNT_NUMBER: 2,
    PIIType.PHONE: 1, PIIType.EMAIL: 0, PIIType.NAME: 0,
}


class PIIGuard:
    def scan(self, text: str) -> PIIDetectionResult:
        entities: List[PIIEntity] = []
        for pii_type, pattern in _PATTERNS.items():
            for m in pattern.finditer(text):
                entities.append(PIIEntity(
                    pii_type=pii_type, value=m.group(),
                    start=m.start(), end=m.end(), confidence=0.95,
                ))

        # Remove spans dominated (fully contained) by higher-priority matches
        filtered: List[PIIEntity] = []
        for e in entities:
            dominated = any(
                other is not e
                and other.start <= e.start and e.end <= other.end
                and _PRIORITY.get(other.pii_type, 0) >= _PRIORITY.get(e.pii_type, 0)
                for other in entities
            )
            if not dominated:
                filtered.append(e)
        entities = filtered

        if entities or _NAME_TRIGGER_RE.search(text):
            entities.extend(self._heuristic_name_scan(text))

        if not entities:
            return PIIDetectionResult(found=False, entities=[], risk_level=RiskLevel.LOW)

        highest = max(_RISK_ORDER[_RISK_MAP[e.pii_type]] for e in entities)
        risk = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH][highest]
        return PIIDetectionResult(
            found=True, entities=entities, risk_level=risk,
            anonymized_text=self.anonymize(text, entities),
        )

    def _heuristic_name_scan(self, text: str) -> List[PIIEntity]:
        entities: List[PIIEntity] = []
        pattern = re.compile(
            r"(?:name|contact|client|customer|employee|advisor|owner|officer)\s*:\s*"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
            re.IGNORECASE,
        )
        for m in pattern.finditer(text):
            val = m.group(1)
            start = m.start(1)
            entities.append(PIIEntity(
                pii_type=PIIType.NAME, value=val,
                start=start, end=start + len(val), confidence=0.80,
            ))
        return entities

    async def async_llm_name_scan(self, text: str) -> List[PIIEntity]:
        """LLM-based name detection. Fail-open — returns [] on any error."""
        try:
            from utils import chat_completion_async
            prompt = (
                "You are a PII detection engine. Find all person names in the text below. "
                'Return only valid JSON: {"names": [{"value": "Full Name", "start": 0, "end": 0}]}. '
                'Return {"names": []} if none found.\n\nText:\n\n' + text[:2000]
            )
            raw = await chat_completion_async(prompt, timeout=15)
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            parsed = json.loads(raw)
            return [
                PIIEntity(
                    pii_type=PIIType.NAME,
                    value=item["value"],
                    start=int(item.get("start", 0)),
                    end=int(item.get("start", 0)) + len(item["value"]),
                    confidence=0.85,
                )
                for item in parsed.get("names", [])
            ]
        except Exception:
            logger.debug("LLM name scan failed (fail-open)", exc_info=True)
            return []

    def anonymize(self, text: str, entities: List[PIIEntity]) -> str:
        result = text
        for entity in sorted(entities, key=lambda e: e.start, reverse=True):
            token = _REDACTION_TOKENS.get(entity.pii_type, "[REDACTED]")
            result = result[: entity.start] + token + result[entity.end :]
        return result

    def enforce_kill_switch(
        self, text: str, user_clearance: ClearanceLevel
    ) -> Tuple[str, bool]:
        result = self.scan(text)
        if not result.found:
            return text, False
        allowed = _CLEARANCE_ALLOWED[user_clearance]
        if result.risk_level not in allowed:
            raise PIIKillSwitchException(
                risk_level=result.risk_level,
                entity_types=list({e.pii_type for e in result.entities}),
            )
        return result.anonymized_text or text, False
