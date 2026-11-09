"""Lint rules for AI-agent tool definitions (MCP / OpenAI / Anthropic schemas)."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2}


@dataclass
class Tool:
    name: str
    description: str
    params: dict  # JSON schema "properties"
    required: list = field(default_factory=list)
    source: str = "?"  # server / file the tool came from
    annotations: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule: str
    severity: str
    tool: str
    source: str
    message: str
    evidence: str = ""


# --- patterns -------------------------------------------------------------

INJECTION_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)", "instruction override"),
    (r"<\s*(important|system|instructions?|secret)\s*>", "hidden pseudo-system tag"),
    (r"do not (tell|inform|mention|reveal)( this)? (to )?(the )?user", "asks the model to hide things from the user"),
    (r"(before|prior to) (using|calling) (this|any other) tool,? (you must |always )?(read|send|include|call)", "pre-call side-channel instruction"),
    (r"(~/\.ssh|id_rsa|\.env\b|aws_secret|api[_ -]?key|private key|mcp\.json|credentials)", "references secrets / credential files"),
    (r"(instead of|rather than) (the )?(user'?s?|requested)", "redirects the user's intent"),
    (r"(send|forward|post|upload|exfiltrat\w*) .{0,40}(to|at) (https?://|[\w.-]+@)", "data sent to an external endpoint"),
    (r"when (the )?(user|you) (ask|request)s? .{0,60}(always|instead)", "conditional behaviour hijack"),
]

SHADOW_PATTERNS = [
    (r"(this tool|you) (must|should) (also|always) (be used|be called|call) (with|before|after|instead of) [`'\"]?(\w+)", "cross-tool shadowing"),
    (r"(other|all) tools? (from|in) (any|other) servers?", "references other servers' tools"),
]

DANGEROUS_VERBS = re.compile(
    r"\b(delete|remove|drop|destroy|wipe|exec|execute|shell|run_command|transfer|pay|send_money|"
    r"rm|kill|shutdown|format|overwrite|purge|truncate|publish|deploy|merge)\b",
    re.I,
)
CONFIRM_HINT = re.compile(r"(confirm|irreversible|cannot be undone|destructive|permanent|ask the user|approval)", re.I)
VAGUE = re.compile(r"^(does stuff|a tool|tool|helper|utility|misc|do (it|things)|todo|tbd|n/?a)\.?$", re.I)

INVISIBLE_CATS = {"Cf", "Co", "Cn"}  # format chars (zero-width, bidi), private use, unassigned


def _approx_tokens(text: str) -> int:
    # ~4 chars/token is the usual rule of thumb for English + JSON
    return max(1, round(len(text) / 4))


def _schema_text(tool: Tool) -> str:
    import json

    return tool.name + tool.description + json.dumps(tool.params) + json.dumps(tool.required)


def _all_text(tool: Tool) -> list[tuple[str, str]]:
    """Every free-text field a model will read: (location, text)."""
    out = [("description", tool.description or "")]
    for pname, p in (tool.params or {}).items():
        if isinstance(p, dict):
            out.append((f"param `{pname}`", str(p.get("description", ""))))
            if "default" in p:
                out.append((f"param `{pname}` default", str(p["default"])))
            for e in p.get("enum", []) or []:
                out.append((f"param `{pname}` enum", str(e)))
    return out


# --- rules ----------------------------------------------------------------

def rule_injection(tool: Tool):
    for loc, text in _all_text(tool):
        low = text.lower()
        for pat, label in INJECTION_PATTERNS:
            m = re.search(pat, low)
            if m:
                yield Finding("TS001-prompt-injection", "critical", tool.name, tool.source,
                              f"Possible tool poisoning in {loc}: {label}.", m.group(0))


def rule_invisible_chars(tool: Tool):
    for loc, text in _all_text(tool) + [("name", tool.name)]:
        bad = [c for c in text if unicodedata.category(c) in INVISIBLE_CATS
               or 0xE0000 <= ord(c) <= 0xE007F]  # unicode "tag" block (ASCII smuggling)
        if bad:
            names = sorted({f"U+{ord(c):04X}" for c in bad})
            yield Finding("TS002-invisible-unicode", "critical", tool.name, tool.source,
                          f"{len(bad)} invisible/smuggled characters in {loc} (humans can't see them, models can).",
                          ", ".join(names[:6]))


def rule_shadowing_text(tool: Tool):
    low = (tool.description or "").lower()
    for pat, label in SHADOW_PATTERNS:
        m = re.search(pat, low)
        if m:
            yield Finding("TS003-tool-shadowing", "high", tool.name, tool.source,
                          f"Description tries to influence other tools: {label}.", m.group(0))


def rule_destructive_without_warning(tool: Tool):
    hay = f"{tool.name} {tool.description}"
    m = DANGEROUS_VERBS.search(hay.replace("_", " ")) or DANGEROUS_VERBS.search(tool.name)
    ann = tool.annotations or {}
    if ann.get("readOnlyHint") is True:
        return
    if m and not CONFIRM_HINT.search(tool.description or "") and ann.get("destructiveHint") is None:
        yield Finding("TS004-unflagged-destructive", "high", tool.name, tool.source,
                      "Looks destructive but has no warning in its description and no `destructiveHint` annotation.",
                      m.group(0))


def rule_vague_description(tool: Tool):
    d = (tool.description or "").strip()
    if not d:
        yield Finding("TS005-missing-description", "medium", tool.name, tool.source,
                      "Tool has no description; the model has to guess when to call it.")
    elif len(d) < 20 or VAGUE.match(d):
        yield Finding("TS006-vague-description", "medium", tool.name, tool.source,
                      "Description is too short/vague to route on reliably.", d[:60])


def rule_param_docs(tool: Tool):
    for pname, p in (tool.params or {}).items():
        if not isinstance(p, dict):
            continue
        if not p.get("description"):
            yield Finding("TS007-undocumented-param", "low", tool.name, tool.source,
                          f"Parameter `{pname}` has no description.")
        if "type" not in p and "enum" not in p and "$ref" not in p and "anyOf" not in p and "oneOf" not in p:
            yield Finding("TS008-untyped-param", "low", tool.name, tool.source,
                          f"Parameter `{pname}` has no type; models will invent formats.")
    for r in tool.required or []:
        if r not in (tool.params or {}):
            yield Finding("TS009-ghost-required", "medium", tool.name, tool.source,
                          f"`{r}` is required but not defined in properties.")


def rule_free_form_command(tool: Tool):
    for pname, p in (tool.params or {}).items():
        if not isinstance(p, dict):
            continue
        if re.fullmatch(r"(cmd|command|script|code|query|sql|shell|expression|eval)", pname, re.I) \
                and p.get("type") == "string" and not p.get("enum") and not p.get("pattern"):
            yield Finding("TS010-free-form-exec", "high", tool.name, tool.source,
                          f"Parameter `{pname}` accepts arbitrary code/commands with no enum or pattern.")


def rule_token_bloat(tool: Tool, budget: int = 400):
    t = _approx_tokens(_schema_text(tool))
    if t > budget:
        yield Finding("TS011-token-bloat", "low", tool.name, tool.source,
                      f"Schema costs ~{t} tokens on every request (budget {budget}).")


def rule_bad_name(tool: Tool):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", tool.name or ""):
        yield Finding("TS012-invalid-name", "medium", tool.name, tool.source,
                      "Name must match ^[a-zA-Z0-9_-]{1,64}$ for most model APIs.")


PER_TOOL_RULES = [
    rule_injection, rule_invisible_chars, rule_shadowing_text, rule_destructive_without_warning,
    rule_vague_description, rule_param_docs, rule_free_form_command, rule_token_bloat, rule_bad_name,
]


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def cross_tool_rules(tools: list[Tool]):
    """Rules that need the whole toolset: collisions and look-alike names across servers."""
    seen: dict[str, Tool] = {}
    for t in tools:
        key = _norm(t.name)
        if key in seen:
            other = seen[key]
            sev = "high" if other.source != t.source else "medium"
            yield Finding("TS013-name-collision", sev, t.name, t.source,
                          f"Collides with `{other.name}` from {other.source}; the model may call the wrong one.",
                          f"{other.source} vs {t.source}")
        else:
            seen[key] = t
    # near-duplicate descriptions across different servers = possible impersonation
    for i, a in enumerate(tools):
        for b in tools[i + 1:]:
            if a.source == b.source or not a.description or not b.description:
                continue
            sa, sb = set(re.findall(r"\w+", a.description.lower())), set(re.findall(r"\w+", b.description.lower()))
            if len(sa) >= 6 and len(sb) >= 6:
                j = len(sa & sb) / len(sa | sb)
                if j >= 0.75 and _norm(a.name) != _norm(b.name):
                    yield Finding("TS014-lookalike-tool", "medium", b.name, b.source,
                                  f"Description is {j:.0%} identical to `{a.name}` ({a.source}) - impersonation or duplicate?")
