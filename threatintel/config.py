"""Configuration loading: JSON file + environment overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_FEED_URLS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
]


@dataclass
class Config:
    """Runtime configuration for the pipeline."""

    base_dir: Path = field(default_factory=Path.cwd)
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.1
    perplexity_model: str = "sonar-pro"
    credentials_file: str = "credentials.json"
    token_file: str = "token.json"
    email_subject: str = "Threat Intelligence Report"
    feed_urls: list[str] = field(default_factory=lambda: list(DEFAULT_FEED_URLS))
    news_days_filter: int = 7
    web_timeout: int = 30
    web_connect_timeout: int = 10
    max_retries: int = 3

    # Secrets (resolved from the environment, never persisted to config.json)
    openai_api_key: str | None = None
    perplexity_api_key: str | None = None
    recipient_email: str | None = None

    @property
    def prompts_dir(self) -> Path:
        return self.base_dir / "prompts"

    def template_path(self, name: str) -> Path:
        return self.base_dir / name


def load_config(config_path: str | Path = "config.json") -> Config:
    """Load *config_path* and overlay environment variables for secrets."""
    path = Path(config_path)
    data: dict = {}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))

    cfg = Config(
        base_dir=path.resolve().parent if path.exists() else Path.cwd(),
        openai_model=data.get("openai_model", Config.openai_model),
        openai_temperature=data.get("openai_temperature", Config.openai_temperature),
        perplexity_model=data.get("perplexity_model", Config.perplexity_model),
        credentials_file=data.get("credentials_file", Config.credentials_file),
        token_file=data.get("token_file", Config.token_file),
        email_subject=data.get("email_subject", Config.email_subject),
        feed_urls=data.get("feed_urls", list(DEFAULT_FEED_URLS)),
        news_days_filter=data.get("news_days_filter", Config.news_days_filter),
        web_timeout=data.get("web_timeout", Config.web_timeout),
        web_connect_timeout=data.get("web_connect_timeout", Config.web_connect_timeout),
        max_retries=data.get("max_retries", Config.max_retries),
    )
    cfg.openai_api_key = os.getenv("OPENAI_API_KEY", data.get("openai_api_key"))
    cfg.perplexity_api_key = os.getenv("PERPLEXITY_API_KEY", data.get("perplexity_api_key"))
    cfg.recipient_email = os.getenv("RECIPIENT_EMAIL", data.get("recipient_email"))
    return cfg
