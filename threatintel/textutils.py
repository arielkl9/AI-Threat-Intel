"""Pure, side-effect-free helpers (HTML cleanup, date filtering, dedup).

These are separated out from the pipeline so they can be unit-tested without
network access or API keys.
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timedelta

import dateutil.parser

log = logging.getLogger(__name__)


def clean_html_content(content: str) -> str:
    """Strip code fences and convert leftover markdown emphasis to HTML."""
    if not content:
        return content
    content = re.sub(r"```html\s*", "", content, flags=re.IGNORECASE)
    content = re.sub(r"```\s*", "", content, flags=re.IGNORECASE)
    content = re.sub(r"- \*\*(.*?)\*\*:", r"- <strong>\1:</strong>", content)
    content = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", content)
    content = re.sub(r"\*(.*?)\*", r"<em>\1</em>", content)
    content = html.unescape(content)
    content = re.sub(r"\n\s*\n", "\n\n", content)
    content = re.sub(r"[ \t]+", " ", content)
    return "\n".join(line.strip() for line in content.split("\n") if line.strip())


def validate_html_structure(html_content: str) -> str:
    """Balance unterminated <div> tags and trim whitespace inside tags."""
    if not html_content:
        return html_content
    open_divs = html_content.count("<div")
    close_divs = html_content.count("</div>")
    if open_divs > close_divs:
        html_content += "</div>" * (open_divs - close_divs)
    return re.sub(r"<([^>]+)>", lambda m: "<" + m.group(1).strip() + ">", html_content)


def filter_news_by_date(news_items: list[dict], days_back: int = 7) -> list[dict]:
    """Keep items whose ``pub_date`` is within *days_back* days, newest first."""
    if not news_items:
        return []
    cutoff = datetime.now() - timedelta(days=days_back)
    filtered: list[dict] = []
    for item in news_items:
        pub_date_str = item.get("pub_date", "")
        if not pub_date_str:
            continue
        try:
            pub_date = dateutil.parser.parse(pub_date_str)
            if pub_date.tzinfo is not None:
                pub_date = pub_date.replace(tzinfo=None)
        except (ValueError, OverflowError) as exc:
            log.warning("Could not parse date %r: %s", pub_date_str, exc)
            continue
        if pub_date >= cutoff:
            item["parsed_date"] = pub_date
            filtered.append(item)
    filtered.sort(key=lambda x: x.get("parsed_date", datetime.min), reverse=True)
    log.info(
        "Date filter: %d -> %d items (within %d days)", len(news_items), len(filtered), days_back
    )
    return filtered


def deduplicate_cve_items(cve_items: list[dict]) -> list[dict]:
    """Collapse duplicate CVE items, keeping the entry with the most data."""
    if not cve_items:
        return cve_items
    unique: dict = {}
    for item in cve_items:
        cve_ids = item.get("cve_ids", [])
        key = tuple(sorted(cve_ids)) if cve_ids else item.get("title", "").lower().strip()
        if key not in unique:
            unique[key] = item
            continue
        existing = unique[key]
        existing_fields = sum(1 for v in existing.values() if v not in (None, [], ""))
        current_fields = sum(1 for v in item.values() if v not in (None, [], ""))
        if current_fields > existing_fields:
            unique[key] = item
    deduped = list(unique.values())
    log.info("Deduplicated CVE items: %d -> %d", len(cve_items), len(deduped))
    return deduped


def parse_cvss(score) -> float | None:
    """Parse a CVSS score that may be a float, int or a 'CVSS X.Y' string."""
    if score is None:
        return None
    try:
        if isinstance(score, str):
            return float(score.replace("CVSS", "").strip())
        return float(score)
    except (ValueError, TypeError):
        return None
