"""toolsmell CLI."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import lint, load_tools, render_json, render_sarif, render_text, score

SEV_ORDER = ["low", "medium", "high", "critical"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="toolsmell",
                                description="Lint AI-agent tool definitions (MCP / OpenAI / Anthropic) for "
                                            "tool poisoning, shadowing, risky capabilities and context bloat.")
    p.add_argument("files", nargs="+", help="JSON files with tool definitions")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--fail-on", choices=SEV_ORDER, default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--min-score", type=int, default=0, help="exit 1 if trust score is below this")
    p.add_argument("--token-budget", type=int, default=400, help="per-tool token budget (default 400)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"toolsmell {__version__}")
    a = p.parse_args(argv)

    tools = []
    for f in a.files:
        try:
            tools.extend(load_tools(f))
        except (OSError, ValueError) as e:
            print(f"toolsmell: cannot read {f}: {e}", file=sys.stderr)
            return 2
    findings = lint(tools, a.token_budget)

    if a.format == "json":
        print(render_json(tools, findings))
    elif a.format == "sarif":
        print(render_sarif(tools, findings, a.files[0]))
    else:
        print(render_text(tools, findings, color=not a.no_color and sys.stdout.isatty()))

    threshold = SEV_ORDER.index(a.fail_on)
    if any(SEV_ORDER.index(f.severity) >= threshold for f in findings):
        return 1
    if score(tools, findings) < a.min_score:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
