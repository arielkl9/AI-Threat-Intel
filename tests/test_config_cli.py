"""Tests for config loading and CLI parsing."""

from __future__ import annotations

import json

from threatintel.cli import build_parser
from threatintel.config import load_config


def test_config_defaults_when_file_missing(tmp_path):
    cfg = load_config(tmp_path / "nope.json")
    assert cfg.openai_model == "gpt-4o-mini"
    assert cfg.feed_urls


def test_config_reads_file_and_env(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"openai_model": "gpt-4o", "news_days_filter": 3}))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    cfg = load_config(path)
    assert cfg.openai_model == "gpt-4o"
    assert cfg.news_days_filter == 3
    assert cfg.openai_api_key == "sk-test"
    assert cfg.prompts_dir == tmp_path / "prompts"


def test_cli_dry_run_flag():
    args = build_parser().parse_args(["--dry-run"])
    assert args.dry_run is True
