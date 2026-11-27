"""Command-line entry point for the threat-intelligence pipeline."""

from __future__ import annotations

import argparse
import logging

from dotenv import load_dotenv

from threatintel import __version__
from threatintel.config import load_config
from threatintel.pipeline import ThreatIntelPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatintel",
        description="Fetch, classify, enrich and email cybersecurity threat intelligence.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", default="config.json", help="path to config.json")
    parser.add_argument(
        "--dry-run", action="store_true", help="generate emails but do not send them"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv()
    cfg = load_config(args.config)
    if not cfg.openai_api_key:
        logging.error("OPENAI_API_KEY is not set. Copy .env.example to .env and fill it in.")
        return 1
    ThreatIntelPipeline(cfg).run(dry_run=args.dry_run)
    return 0
