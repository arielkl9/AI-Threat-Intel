"""Tests for the pure text/data helpers (no network, no API keys)."""

from __future__ import annotations

from datetime import datetime, timedelta

from threatintel.textutils import (
    clean_html_content,
    deduplicate_cve_items,
    filter_news_by_date,
    parse_cvss,
    validate_html_structure,
)


def test_clean_html_strips_code_fences_and_markdown():
    out = clean_html_content("```html\n**Bold** and *em*\n```")
    assert "```" not in out
    assert "<strong>Bold</strong>" in out
    assert "<em>em</em>" in out


def test_clean_html_empty():
    assert clean_html_content("") == ""


def test_validate_html_balances_divs():
    assert validate_html_structure("<div><div>x").count("</div>") == 2


def test_filter_news_by_date_keeps_recent_only():
    recent = (datetime.now() - timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    old = (datetime.now() - timedelta(days=30)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    items = [{"title": "new", "pub_date": recent}, {"title": "old", "pub_date": old}]
    kept = filter_news_by_date(items, days_back=7)
    assert [i["title"] for i in kept] == ["new"]


def test_filter_news_handles_missing_and_bad_dates():
    items = [{"title": "no date"}, {"title": "bad", "pub_date": "not a date"}]
    assert filter_news_by_date(items, days_back=7) == []


def test_deduplicate_keeps_most_complete():
    sparse = {"title": "Dup", "cve_ids": [], "ioc": None}
    rich = {"title": "Dup", "cve_ids": [], "ioc": ["1.2.3.4"], "affected_systems": ["x"]}
    out = deduplicate_cve_items([sparse, rich])
    assert len(out) == 1
    assert out[0]["ioc"] == ["1.2.3.4"]


def test_parse_cvss_variants():
    assert parse_cvss("9.8") == 9.8
    assert parse_cvss("CVSS 7.5") == 7.5
    assert parse_cvss(5) == 5.0
    assert parse_cvss("n/a") is None
    assert parse_cvss(None) is None
