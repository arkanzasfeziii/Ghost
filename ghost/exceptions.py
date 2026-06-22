"""Custom exception hierarchy for Ghost."""

from __future__ import annotations


class GhostError(Exception):
    """Base exception for all Ghost errors."""


class ModuleError(GhostError):
    """Raised when a module encounters a runtime error."""


class EncodingError(GhostError):
    """Raised when payload encoding fails."""


class DependencyError(GhostError):
    """Raised when a required dependency is missing."""

    def __init__(self, package: str) -> None:
        super().__init__(f"Missing: {package}. Install with: pip install {package}")
        self.package = package
