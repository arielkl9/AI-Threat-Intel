# AI Threat Intelligence Pipeline

An automated pipeline that monitors cybersecurity RSS feeds, classifies and
enriches each item with LLMs (OpenAI + Perplexity), researches CVEs, renders
professional HTML email reports, and delivers them via the Gmail API.

## What it does

1. **Fetch** RSS feeds from major sources (The Hacker News, BleepingComputer).
2. **Classify & enrich** each article with Perplexity (CVE vs. News, IOCs,
   affected systems, action items).
3. **Research CVEs** individually and score them (Critical ≥ CVSS 9.0).
4. **Render** categorised HTML emails from templates, with deduplication.
5. **Send** the CVE and news digests over the Gmail API.

## Install

```bash
git clone https://github.com/arielkl9/AI-Threat-Intel.git
cd AI-Threat-Intel
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

## Configure

```bash
cp .env.example .env     # then fill in your keys
```

`.env`:

```
OPENAI_API_KEY=sk-...
PERPLEXITY_API_KEY=pplx-...
RECIPIENT_EMAIL=security-team@example.com
```

Gmail: create an OAuth2 **Desktop** client in Google Cloud (with the Gmail API
enabled and the `gmail.send` scope), download it as `credentials.json` into the
project root. On first send you'll authorise once in the browser; a refreshable
`token.json` is then written automatically. All three credential files are
git-ignored.

Non-secret settings (models, feeds, `news_days_filter`, timeouts) live in
`config.json`.

## Run

```bash
threatintel              # full run: fetch, enrich, render, send
threatintel --dry-run    # generate the emails but do not send
threatintel -v           # debug logging
threatintel -c custom_config.json
```

## Project layout

```
threatintel/        installable package
  config.py         config dataclass + env overlay
  models.py         ThreatIntelItem (legacy <-> unified CVE shim)
  feeds / pipeline  fetch, enrich, research, categorise, render, send
  textutils.py      pure helpers (HTML cleanup, date filter, dedup) - unit tested
  gmail.py          Gmail API sender (with token refresh)
  cli.py            argparse entry point
prompts/            externalised LLM prompts (edit without touching code)
*.html              email templates
tests/              pytest suite for the pure helpers
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

## What changed in 2.0

- Split the single 1,085-line script into an installable `threatintel` package
  with an `argparse` CLI and a `--dry-run` mode.
- Fixed real bugs: the script never called `run()` (so it did nothing); the
  module-level `logger` was only defined under `__main__` (NameError on import);
  `feedparser` was missing from `requirements.txt`; and the generation date was
  hardcoded to `2025-07-11`.
- Gmail sender now refreshes expired tokens instead of failing.
- Corrected the README clone URL (was `arielkl-wix/AI-Threat-Hunting`).
- Added pyproject packaging, a pytest suite, ruff config, GitHub Actions CI,
  `.env.example`, and a dataclass-based config with environment overlay.

## License

MIT — see [LICENSE](LICENSE).
