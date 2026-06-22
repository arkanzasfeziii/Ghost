"""Banner, legal warning, and result formatting."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ghost.config import LEGAL_WARNING, TOOL_NAME, VERSION
from ghost.logger import console, ok, HAS_RICH
from ghost.models import EngagementContext

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False


def print_banner() -> None:
    if HAS_PYFIGLET and HAS_RICH:
        banner = pyfiglet.figlet_format("Ghost", font="slant")
        console.print(f"[bold red]{banner}[/bold red]", highlight=False)
        console.print(f"  [dim]Evasion & Payload Crafting Framework  v{VERSION}[/dim]")
        console.print(f"  [dim]MITRE ATT&CK: T1055 | T1027 | T1218 | T1562 | T1497 | T1106[/dim]")
        console.print(f"  [dim]{'─' * 52}[/dim]\n")
    else:
        print(f"\n  {TOOL_NAME} v{VERSION}\n")


def print_legal(skip: bool) -> bool:
    if HAS_RICH:
        console.print(LEGAL_WARNING)
    else:
        print(LEGAL_WARNING)
    if skip:
        return True
    try:
        confirm = input("\n  Do you have written authorization? [y/N]: ").strip().lower()
        return confirm in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        return False


def dump_results(ctx: EngagementContext) -> None:
    if HAS_RICH:
        from rich.table import Table
        from rich import box as rich_box

        table = Table(title="Engagement Summary", box=rich_box.ROUNDED)
        table.add_column("Module", style="cyan")
        table.add_column("Action", style="white")
        table.add_column("Status", style="green")
        table.add_column("Severity", style="yellow")
        table.add_column("Notes", style="dim")

        status_styles = {"ok": "green", "fail": "red", "critical": "bold red"}
        severity_styles = {"info": "dim", "low": "blue", "medium": "yellow",
                           "high": "bold yellow", "critical": "bold red"}

        for r in ctx.results:
            ss = status_styles.get(r.status, "white")
            sv = severity_styles.get(r.severity, "white")
            table.add_row(
                r.module, r.action,
                f"[{ss}]{r.status.upper()}[/{ss}]",
                f"[{sv}]{r.severity.upper()}[/{sv}]",
                r.notes[:60] + ("..." if len(r.notes) > 60 else ""),
            )
        console.print(table)
    else:
        for r in ctx.results:
            print(f"  [{r.status.upper()}] [{r.module}] {r.action}: {r.notes[:60]}")

    ok_count = sum(1 for r in ctx.results if r.status == "ok")
    fail_count = sum(1 for r in ctx.results if r.status == "fail")
    print(f"\n  Total: {len(ctx.results)} | OK: {ok_count} | FAIL: {fail_count}")
    print(f"  Artifacts: {os.path.abspath(ctx.output_dir)}")

    if ctx.output_file:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "target_os": ctx.target_os, "arch": ctx.arch,
            "results": [{"module": r.module, "action": r.action,
                         "status": r.status, "severity": r.severity,
                         "notes": r.notes} for r in ctx.results],
        }
        Path(ctx.output_file).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        ok(f"Report saved: {ctx.output_file}")
