"""Artifact file writer for generated payloads and templates."""

from __future__ import annotations

import os

from ghost.models import EngagementContext


def save_artifact(ctx: EngagementContext, filename: str, content: str) -> str:
    os.makedirs(ctx.output_dir, exist_ok=True)
    path = os.path.join(ctx.output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
