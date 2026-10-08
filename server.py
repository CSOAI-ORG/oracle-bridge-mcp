#!/usr/bin/env python3
"""
Oracle (PL/SQL / Forms / DB) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse PL/SQL, map to modern, and govern. Sibling of cobol-bridge-mcp.
Tools: parse_plsql · extract_tables · map_to_modern · govern_oracle
"""
from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x: FastMCP renamed MCPServer
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import re

mcp = FastMCP("Oracle Bridge", instructions="Bridge Oracle PL/SQL legacy to ONE OS — parse, map, govern.")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""


class PLSQLParsed(BaseModel):
    packages: List[str] = Field(default_factory=list)
    procedures: List[str] = Field(default_factory=list)
    functions: List[str] = Field(default_factory=list)
    cursors: List[str] = Field(default_factory=list)
    tables: List[str] = Field(default_factory=list)
    line_count: int = 0


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


@mcp.tool()
def parse_plsql(source_code: str) -> PLSQLParsed:
    """Parse Oracle PL/SQL: packages, procedures, functions, cursors, referenced tables."""
    s = source_code
    return PLSQLParsed(
        packages=re.findall(r"\bPACKAGE\s+(?:BODY\s+)?(\w+)", s, re.I)[:30],
        procedures=re.findall(r"\bPROCEDURE\s+(\w+)", s, re.I)[:50],
        functions=re.findall(r"\bFUNCTION\s+(\w+)", s, re.I)[:50],
        cursors=re.findall(r"\bCURSOR\s+(\w+)", s, re.I)[:50],
        tables=sorted(set(re.findall(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([A-Za-z_][\w$]*)", s, re.I)))[:50],
        line_count=len(s.splitlines()),
    )


@mcp.tool()
def extract_tables(source_code: str) -> Dict[str, Any]:
    """List the tables the PL/SQL touches (data-lineage + migration scope)."""
    p = parse_plsql(source_code)
    return {"tables": p.tables, "count": len(p.tables),
            "note": "Each table → modern schema; map data lineage for governance."}


@mcp.tool()
def map_to_modern(source_code: str) -> Dict[str, Any]:
    """Map PL/SQL shape to a modern service (procs/functions->endpoints, tables->models)."""
    p = parse_plsql(source_code)
    return {"source": "Oracle PL/SQL", "target": "modern service",
            "endpoints": (p.procedures + p.functions) or ["main"],
            "data_models": p.tables, "modules": p.packages}


@mcp.tool()
def govern_oracle(source_code: str) -> Governance:
    """Governance: SQL-injection + privilege + data-lineage surface (attestable for CSOAI)."""
    _sigil("G", "oracle|govern_oracle")
    flags = []
    if re.search(r"EXECUTE\s+IMMEDIATE|DBMS_SQL", source_code, re.I):
        flags.append("Dynamic SQL (EXECUTE IMMEDIATE/DBMS_SQL) — injection review on migration")
    if re.search(r"\bGRANT\s+", source_code, re.I):
        flags.append("Inline GRANTs — review least-privilege")
    return Governance(risk_flags=flags,
                      frameworks=["SOX (ITGC)", "GDPR", "DORA", "ISO 27001"],
                      note="CSOAI governs the bridge: code + data lineage attestable on the ledger.")


# ---------------------------------------------------------------------------
# MCP 2026-07-28 wire - header-add migration (2026-10-08)
# ---------------------------------------------------------------------------
# stdio carries no HTTP headers, so Mcp-Method / Mcp-Name are not applicable to
# this transport at runtime. When oracle-bridge-mcp is exposed over HTTP, route the ingress
# through the vendored mcp2026_shim (ShimASGI): it validates Mcp-Method /
# Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" into every
# request, strips Mcp-Session-Id and answers legacy initialize / server-discover
# locally (the session header is never emitted - stateless wire).
# Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md (3) + (4).
# ---------------------------------------------------------------------------


def http_app():
    """ASGI app for HTTP exposure, wrapped in the 2026-07-28 wire shim.

    stdio (``mcp.run()``) needs no shim; this is the enable path once the
    server is fronted by an HTTP transport. Bodies are buffered, so responses
    are requested in JSON mode rather than SSE.
    """
    from mcp2026_shim import WIRE_2026, ShimASGI, ShimConfig

    return ShimASGI(
        mcp.streamable_http_app(json_response=True),
        ShimConfig(
            protocol_version=WIRE_2026,
            server_info={"name": "oracle-bridge-mcp", "version": "0.1.0"},
        ),
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
