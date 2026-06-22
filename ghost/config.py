"""Constants and configuration for Ghost."""

from __future__ import annotations

from ghost import __version__, __author__

TOOL_NAME = "Ghost Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "ghost"

LEGAL_WARNING = """\
[bold red]WARNING — AUTHORIZED USE ONLY[/bold red]

Ghost Framework is a professional red team and penetration testing tool.
Unauthorized access to computer systems is illegal under:
  - Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030
  - Computer Misuse Act 1990 (UK)
  - Applicable local cybercrime legislation

You MUST have explicit written authorization before using this tool
against any target. The author assumes no liability for misuse.

Proceed only if you have a signed Rules of Engagement (RoE) document."""
