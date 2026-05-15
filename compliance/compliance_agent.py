"""
Agentic RAG compliance engine using a ReAct (Reason + Act) loop.

Flow per iteration:
  1. THINK  — LLM produces {thought, action, action_input, final_answer}
  2. ACT    — call the named MCP tool
  3. GUARD  — PIIGuard intercepts the tool result before it touches the LLM context
  4. OBSERVE — safe result appended to context window; loop continues

On FINISH the agent seals a ForensicSnapshot and persists it via the MCP store tool.
"""
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from compliance.forensic import (
    EvidenceItem, ForensicSnapshot, ReActStep,
    export_snapshot_json, generate_snapshot,
)
from compliance.mcp_server import mcp, MCPToolResult
from compliance.pii_guard import ClearanceLevel, PIIGuard, PIIKillSwitchException

logger = logging.getLogger(__name__)

MAX_REACT_STEPS = 6

SYSTEM_PROMPT = """You are a regulatory compliance analyst AI specialised in EU financial regulation.
You map an organisation's ICT security controls against DORA and MiFID II articles to identify
compliance status and gaps.

You have access to these MCP tools:
- get_dora_article(article_id)         – fetch DORA article text and requirements
- get_mifid_article(article_id)        – fetch MiFID II article text and requirements
- query_controls_db(article_id, control_type, status) – query internal ICT controls database

Reason step by step. For EVERY step output ONLY a single valid JSON object — no prose, no markdown fences:
{
  "thought": "<your reasoning>",
  "action": "<tool_name or FINISH>",
  "action_input": {"param": "value"},
  "final_answer": null
}

When action is "FINISH" set final_answer to:
{
  "matched_controls": [{"control_id": "ICT-XXX", "control_name": "...", "articles": [...], "status": "..."}],
  "gap_analysis": [{"article": "Art.X", "requirement": "...", "gap": "..."}],
  "compliance_score": <float 0-100>,
  "summary": "<2-3 sentence executive summary>"
}
Keep final_answer null on all non-FINISH steps.
"""

_MOCK_STEPS = [
    json.dumps({
        "thought": "The query asks to map ICT controls to DORA Art.9. I should first retrieve the article requirements.",
        "action": "get_dora_article",
        "action_input": {"article_id": "Art.9"},
        "final_answer": None,
    }),
    json.dumps({
        "thought": "I now have the Art.9 requirements. Let me query controls mapped to Art.9.",
        "action": "query_controls_db",
        "action_input": {"article_id": "Art.9"},
        "final_answer": None,
    }),
    json.dumps({
        "thought": (
            "ICT-005 and ICT-007 are fully implemented. ICT-008 is partial. "
            "Art.9 also requires a DDoS response runbook which is not covered — that is a gap."
        ),
        "action": "FINISH",
        "action_input": {},
        "final_answer": {
            "matched_controls": [
                {"control_id": "ICT-005", "control_name": "Data Protection & Encryption Controls", "articles": ["Art.9"], "status": "implemented"},
                {"control_id": "ICT-007", "control_name": "Network Segmentation & Access Control", "articles": ["Art.9"], "status": "implemented"},
                {"control_id": "ICT-008", "control_name": "Vulnerability Management & Patch Cycle", "articles": ["Art.6", "Art.9"], "status": "partial"},
            ],
            "gap_analysis": [
                {
                    "article": "Art.9",
                    "requirement": "Document a DDoS response runbook",
                    "gap": "No DDoS response runbook exists. ICT-008 partial: 2 on-prem systems have unresolved Critical findings.",
                }
            ],
            "compliance_score": 72.5,
            "summary": (
                "3 of 6 DORA Art.9 requirements are fully covered by implemented controls. "
                "ICT-008 is partially compliant with outstanding Critical vulnerability findings. "
                "A DDoS response runbook must be created to close the remaining gap."
            ),
        },
    }),
]


class ComplianceAgent:
    def __init__(self, user_clearance: ClearanceLevel = ClearanceLevel.ANALYST) -> None:
        self.user_clearance = user_clearance
        self.pii_guard = PIIGuard()
        self._steps: List[ReActStep] = []

    async def run(self, query: str, regulation: str, user_id: str) -> Dict[str, Any]:
        context: List[str] = [
            f"SYSTEM:\n{SYSTEM_PROMPT}",
            f"USER QUERY: {query}",
            f"TARGET REGULATION: {regulation}",
            "Available tools: get_dora_article, get_mifid_article, query_controls_db",
        ]
        self._steps = []
        evidence: List[EvidenceItem] = []
        final_answer: Optional[dict] = None

        for step_num in range(1, MAX_REACT_STEPS + 1):
            raw_llm = await self._get_llm_response("\n\n".join(context))

            try:
                step_data = self._parse_json(raw_llm)
            except ValueError as exc:
                logger.warning("Step %d JSON parse failed: %s", step_num, exc)
                break

            thought = step_data.get("thought", "")
            action = step_data.get("action", "")
            action_input = step_data.get("action_input") or {}

            if action == "FINISH":
                final_answer = step_data.get("final_answer") or {}
                self._steps.append(ReActStep(
                    step_number=step_num, thought=thought,
                    action="FINISH", action_input={},
                    observation="Analysis complete.",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

            tool_result: MCPToolResult = await mcp.call_tool(action, **action_input)
            raw_obs = (
                json.dumps(tool_result.data, default=str)
                if tool_result.success else f"ERROR: {tool_result.error}"
            )

            # PII Kill-Switch — intercept BEFORE appending to LLM context
            try:
                safe_obs, _ = self.pii_guard.enforce_kill_switch(raw_obs, self.user_clearance)
            except PIIKillSwitchException as exc:
                safe_obs = f"[BLOCKED by PII Kill-Switch: {exc}]"
                logger.info("PII Kill-Switch fired at step %d", step_num)

            self._steps.append(ReActStep(
                step_number=step_num, thought=thought,
                action=action, action_input=action_input,
                observation=safe_obs[:800],
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

            if tool_result.success and tool_result.data:
                evidence.extend(self._extract_evidence(action, action_input, tool_result.data))

            context.append(
                f"STEP {step_num}:\nThought: {thought}\n"
                f"Action: {action}({json.dumps(action_input)})\n"
                f"Observation: {safe_obs[:600]}"
            )

        if final_answer is None:
            final_answer = self._fallback_answer()

        snapshot = generate_snapshot(
            query=query, regulation=regulation, user_id=user_id,
            agent_steps=self._steps,
            matched_controls=final_answer.get("matched_controls", []),
            gap_analysis=final_answer.get("gap_analysis", []),
            compliance_score=float(final_answer.get("compliance_score", 0.0)),
            evidence=evidence,
        )

        await mcp.call_tool("store_forensic_snapshot", snapshot_data=self._to_db_dict(snapshot))

        return {
            "query": query,
            "regulation": regulation,
            "analysis": final_answer,
            "agent_steps": [asdict(s) for s in self._steps],
            "snapshot": export_snapshot_json(snapshot),
        }

    async def _get_llm_response(self, prompt: str) -> str:
        if os.getenv("MOCK_LLM", "false").lower() == "true":
            return _MOCK_STEPS[min(len(self._steps), len(_MOCK_STEPS) - 1)]
        from utils import chat_completion_async
        return await chat_completion_async(prompt, timeout=60)

    @staticmethod
    def _parse_json(raw: str) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        start, end = text.find("{"), text.rfind("}") + 1
        if start == -1 or end == 0:
            raise ValueError(f"No JSON in LLM output: {raw[:200]}")
        return json.loads(text[start:end])

    @staticmethod
    def _extract_evidence(action: str, action_input: dict, data: Any) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        if action in ("get_dora_article", "get_mifid_article") and isinstance(data, dict):
            items.append(EvidenceItem(
                source_id=data.get("id", action_input.get("article_id", "unknown")),
                source_type="regulatory_article",
                document=data.get("text_excerpt", "")[:500],
                version="DORA 2022/2554" if action == "get_dora_article" else "MiFID II 2014/65/EU",
                rationale=f"Regulatory requirements for {data.get('article_number', '')}",
            ))
        elif action == "query_controls_db" and isinstance(data, list):
            for ctrl in data:
                items.append(EvidenceItem(
                    source_id=ctrl.get("id", "unknown"),
                    source_type="ict_control",
                    document=ctrl.get("description", "")[:300],
                    version=ctrl.get("version", "unknown"),
                    rationale=(
                        f"Control '{ctrl.get('name', '')}' maps to "
                        f"{ctrl.get('dora_articles', [])} with status '{ctrl.get('status', '')}'"
                    ),
                ))
        return items

    @staticmethod
    def _fallback_answer() -> dict:
        return {
            "matched_controls": [],
            "gap_analysis": [{"article": "unknown", "requirement": "Analysis incomplete",
                               "gap": "Agent loop exhausted without a final answer."}],
            "compliance_score": 0.0,
            "summary": "Compliance analysis could not be completed. Please retry.",
        }

    @staticmethod
    def _to_db_dict(snapshot: ForensicSnapshot) -> dict:
        return {
            "snapshot_id": snapshot.snapshot_id,
            "user_id": snapshot.user_id,
            "query": snapshot.query,
            "regulation": snapshot.regulation,
            "result_json": {
                "matched_controls": snapshot.matched_controls,
                "gap_analysis": snapshot.gap_analysis,
            },
            "compliance_score": snapshot.compliance_score,
            "agent_steps": [asdict(s) for s in snapshot.agent_steps],
            "signature": snapshot.auditor_signature,
        }
