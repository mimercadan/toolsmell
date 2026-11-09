"""Load tool definitions from many formats, run rules, score, and render reports."""
from __future__ import annotations

import json
from pathlib import Path

from .rules import (PER_TOOL_RULES, SEVERITY_WEIGHT, Finding, Tool, cross_tool_rules,
                    rule_token_bloat)


def _from_obj(obj: dict, source: str) -> Tool | None:
    # OpenAI: {"type":"function","function":{...}}
    if obj.get("type") == "function" and isinstance(obj.get("function"), dict):
        obj = obj["function"]
    name = obj.get("name")
    if not name:
        return None
    schema = obj.get("inputSchema") or obj.get("input_schema") or obj.get("parameters") or {}
    return Tool(
        name=name,
        description=obj.get("description", "") or "",
        params=schema.get("properties", {}) or {},
        required=schema.get("required", []) or [],
        source=source,
        annotations=obj.get("annotations", {}) or {},
    )


def load_tools(path: str | Path) -> list[Tool]:
    """Accepts: a list of tools, {"tools": [...]} (MCP tools/list result or JSON-RPC response),
    or {"servers": {"name": {"tools": [...]}}} for multi-server audits."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    default_src = path.stem
    tools: list[Tool] = []

    def add(items, src):
        for it in items or []:
            if isinstance(it, dict):
                t = _from_obj(it, src)
                if t:
                    tools.append(t)

    if isinstance(data, list):
        add(data, default_src)
    elif isinstance(data, dict):
        if "result" in data and isinstance(data["result"], dict):  # raw JSON-RPC response
            data = data["result"]
        if "servers" in data:
            for sname, sdef in data["servers"].items():
                add(sdef.get("tools") if isinstance(sdef, dict) else sdef, sname)
        elif "tools" in data:
            add(data["tools"], data.get("server", default_src))
        else:
            add([data], default_src)
    return tools


def lint(tools: list[Tool], token_budget: int = 400) -> list[Finding]:
    findings: list[Finding] = []
    for t in tools:
        for rule in PER_TOOL_RULES:
            if rule is rule_token_bloat:
                findings.extend(rule(t, token_budget))
            else:
                findings.extend(rule(t))
    findings.extend(cross_tool_rules(tools))
    order = list(SEVERITY_WEIGHT)
    findings.sort(key=lambda f: (order.index(f.severity), f.source, f.tool, f.rule))
    return findings


def score(tools: list[Tool], findings: list[Finding]) -> int:
    """0-100 trust score. Each finding costs its weight, normalised by toolset size,
    but any critical finding caps the score at 40."""
    if not tools:
        return 100
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    s = max(0, round(100 - penalty / max(1, len(tools) ** 0.5)))
    if any(f.severity == "critical" for f in findings):
        s = min(s, 40)
    return s


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def total_tokens(tools: list[Tool]) -> int:
    from .rules import _approx_tokens, _schema_text
    return sum(_approx_tokens(_schema_text(t)) for t in tools)


# --- renderers -------------------------------------------------------------

ICON = {"critical": "✖", "high": "▲", "medium": "●", "low": "·"}
COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[2m"}
RESET = "\033[0m"


def render_text(tools, findings, color=True) -> str:
    c = (lambda k: COLOR[k]) if color else (lambda k: "")
    r = RESET if color else ""
    lines = []
    for f in findings:
        ev = f"  ← {f.evidence!r}" if f.evidence else ""
        lines.append(f"{c(f.severity)}{ICON[f.severity]} {f.severity.upper():8}{r} "
                     f"[{f.source}] {f.tool}: {f.message}{ev}  ({f.rule})")
    s = score(tools, findings)
    counts = {k: sum(1 for f in findings if f.severity == k) for k in SEVERITY_WEIGHT}
    srcs = sorted({t.source for t in tools})
    lines.append("")
    lines.append(f"Scanned {len(tools)} tools from {len(srcs)} server(s): {', '.join(srcs)}")
    lines.append(f"Context cost: ~{total_tokens(tools)} tokens per request just for tool schemas")
    lines.append("Findings: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    lines.append(f"Trust score: {s}/100  (grade {grade(s)})")
    return "\n".join(lines)


def render_json(tools, findings) -> str:
    s = score(tools, findings)
    return json.dumps({
        "score": s, "grade": grade(s), "tools": len(tools), "approx_tokens": total_tokens(tools),
        "findings": [f.__dict__ for f in findings],
    }, indent=2, ensure_ascii=False)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def render_sarif(tools, findings, artifact: str) -> str:
    rules = sorted({f.rule for f in findings})
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "toolsmell", "informationUri": "https://github.com/mimercadan/toolsmell",
                                "rules": [{"id": r, "name": r.split("-", 1)[1]} for r in rules]}},
            "results": [{
                "ruleId": f.rule, "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"[{f.source}] {f.tool}: {f.message}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact}}}],
            } for f in findings],
        }],
    }, indent=2, ensure_ascii=False)
