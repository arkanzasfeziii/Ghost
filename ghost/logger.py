"""Rich-based terminal output helpers."""

from __future__ import annotations

try:
    from rich.console import Console
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


def _print(msg: str) -> None:
    if console:
        console.print(msg)
    else:
        print(msg)


def info(msg: str) -> None:
    _print(f"  [bold cyan][INFO][/bold cyan]  {msg}" if HAS_RICH else f"  [INFO]  {msg}")


def ok(msg: str) -> None:
    _print(f"  [bold green][ OK ][/bold green]  {msg}" if HAS_RICH else f"  [ OK ]  {msg}")


def warn(msg: str) -> None:
    _print(f"  [bold yellow][WARN][/bold yellow]  {msg}" if HAS_RICH else f"  [WARN]  {msg}")


def crit(msg: str) -> None:
    _print(f"  [bold red][CRIT][/bold red]  {msg}" if HAS_RICH else f"  [CRIT]  {msg}")


def section(title: str) -> None:
    if HAS_RICH:
        console.print()
        console.print(Panel(f"[bold white]{title}[/bold white]", border_style="bright_blue", width=72))
    else:
        print(f"\n  {'─' * 60}")
        print(f"    {title}")
        print(f"  {'─' * 60}\n")
