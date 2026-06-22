"""Abstract base class for all Ghost modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ghost.models import EngagementContext


class BaseModule(ABC):

    name: str = "base"

    @abstractmethod
    def run(self, ctx: EngagementContext) -> None:
        ...
