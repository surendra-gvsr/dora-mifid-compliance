"""
MCP-style tool registry for the compliance agent.

Implements the Model Context Protocol pattern as an in-process tool registry
rather than a separate HTTP server, making the demo fully self-contained while
faithfully demonstrating the Thought → Action → Observation loop that MCP enables.
"""
import asyncio
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class MCPToolResult:
    tool_name: str
    success: bool
    data: Any
    error: Optional[str] = None


class MCPToolRegistry:
    """
    Decorator-based tool registry. The compliance agent calls tools by name
    via call_tool(), mirroring how an MCP client dispatches to an MCP server.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, Callable] = {}

    def tool(self, fn: Callable) -> Callable:
        self._tools[fn.__name__] = fn
        return fn

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())

    async def call_tool(self, name: str, **kwargs) -> MCPToolResult:
        if name not in self._tools:
            return MCPToolResult(
                tool_name=name, success=False, data=None,
                error=f"Unknown MCP tool: '{name}'. Available: {self.list_tools()}",
            )
        fn = self._tools[name]
        try:
            if inspect.iscoroutinefunction(fn):
                result = await fn(**kwargs)
            else:
                result = fn(**kwargs)
            return MCPToolResult(tool_name=name, success=True, data=result)
        except Exception as exc:
            logger.exception("MCP tool '%s' raised an error", name)
            return MCPToolResult(tool_name=name, success=False, data=None, error=str(exc))


mcp = MCPToolRegistry()


@mcp.tool
def query_controls_db(
    article_id: Optional[str] = None,
    control_type: Optional[str] = None,
    status: Optional[str] = None,
) -> List[dict]:
    from compliance.controls_db import query_controls
    return [r.__dict__ for r in query_controls(
        article_id=article_id, control_type=control_type, status=status
    )]


@mcp.tool
def get_dora_article(article_id: str) -> Optional[dict]:
    from compliance.regulatory_kb import get_dora_article as _get
    article = _get(article_id)
    return article.__dict__ if article else None


@mcp.tool
def get_mifid_article(article_id: str) -> Optional[dict]:
    from compliance.regulatory_kb import get_mifid_article as _get
    article = _get(article_id)
    return article.__dict__ if article else None


@mcp.tool
async def store_forensic_snapshot(snapshot_data: dict) -> dict:
    from database import SessionLocal
    from compliance.models import ComplianceSnapshot

    db = SessionLocal()
    try:
        record = ComplianceSnapshot(**snapshot_data)
        db.add(record)
        db.commit()
        db.refresh(record)
        return {"snapshot_id": record.snapshot_id, "status": "persisted"}
    finally:
        db.close()
