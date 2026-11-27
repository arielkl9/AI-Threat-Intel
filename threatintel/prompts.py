"""Load and fill prompt/template files from the configured directories."""

from __future__ import annotations

from pathlib import Path


def load_prompt(prompts_dir: Path, name: str) -> str:
    """Read a prompt file (e.g. 'news_batch.txt') from *prompts_dir*."""
    return (prompts_dir / name).read_text(encoding="utf-8")


def fill(template: str, **replacements: str) -> str:
    """Replace ``{key}`` placeholders in *template* with the given values."""
    for key, value in replacements.items():
        template = template.replace("{" + key + "}", value)
    return template
