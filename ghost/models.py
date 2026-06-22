"""Data models used across all Ghost modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class AttackResult:
    module: str
    action: str
    status: str
    severity: str
    notes: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class EngagementContext:
    payload_type: str = "staged"
    target_os: str = "windows"
    arch: str = "x64"
    output_dir: str = "./ghost_output"
    lhost: str = "0.0.0.0"
    lport: int = 4444
    encoding_iterations: int = 3
    results: List[AttackResult] = field(default_factory=list)
    output_file: Optional[str] = None
