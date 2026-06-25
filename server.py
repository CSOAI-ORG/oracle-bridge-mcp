#!/usr/bin/env python3
"""
Oracle (PL/SQL / Forms / DB) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse PL/SQL, map to modern, and govern. Sibling of cobol-bridge-mcp.
Tools: parse_plsql · extract_tables · map_to_modern · govern_oracle
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import re

mcp = FastMCP("Oracle Bridge", instructions="Bridge Oracle PL/SQL legacy to ONE OS — parse, map, govern.")


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
    flags = []
    if re.search(r"EXECUTE\s+IMMEDIATE|DBMS_SQL", source_code, re.I):
        flags.append("Dynamic SQL (EXECUTE IMMEDIATE/DBMS_SQL) — injection review on migration")
    if re.search(r"\bGRANT\s+", source_code, re.I):
        flags.append("Inline GRANTs — review least-privilege")
    return Governance(risk_flags=flags,
                      frameworks=["SOX (ITGC)", "GDPR", "DORA", "ISO 27001"],
                      note="CSOAI governs the bridge: code + data lineage attestable on the ledger.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
