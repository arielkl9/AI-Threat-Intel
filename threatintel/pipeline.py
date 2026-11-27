"""Pipeline orchestration: fetch -> enrich -> research -> render -> send."""

from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import feedparser
import requests
from openai import OpenAI

from threatintel.config import Config
from threatintel.gmail import EmailSender
from threatintel.models import ThreatIntelItem
from threatintel.prompts import fill, load_prompt
from threatintel.textutils import (
    clean_html_content,
    deduplicate_cve_items,
    filter_news_by_date,
    parse_cvss,
    validate_html_structure,
)

log = logging.getLogger(__name__)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


class ThreatIntelPipeline:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.openai_client = OpenAI(api_key=cfg.openai_api_key) if cfg.openai_api_key else None
        self.email_sender = EmailSender(cfg.credentials_file, cfg.token_file, cfg.recipient_email)
        if cfg.perplexity_api_key:
            self.perplexity_client = OpenAI(
                api_key=cfg.perplexity_api_key, base_url="https://api.perplexity.ai"
            )
        else:
            self.perplexity_client = None
            log.warning("Perplexity API key not found; enrichment/research will be skipped")

    # --- fetching ----------------------------------------------------------

    def fetch_feeds(self, urls: list[str]) -> list[dict]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml,application/xml,text/xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.5",
        }
        feeds = []
        for url in urls:
            try:
                log.info("Fetching feed: %s", url)
                resp = requests.get(url, headers=headers, timeout=self.cfg.web_timeout)
                if resp.status_code == 200:
                    feeds.append({"url": url, "content": feedparser.parse(resp.content)})
                else:
                    log.warning("Failed to fetch %s: HTTP %s", url, resp.status_code)
            except requests.RequestException as exc:
                log.error("Error fetching %s: %s", url, exc)
        return feeds

    def parse_xml_feeds(self, feeds: list[dict]) -> list[ThreatIntelItem]:
        items: list[ThreatIntelItem] = []
        for feed in feeds:
            for entry in feed["content"].entries:
                title = entry.get("title", "").strip()
                if not title:
                    continue
                items.append(
                    ThreatIntelItem(
                        title=title,
                        description=entry.get("description", "").strip(),
                        link=entry.get("link", "").strip(),
                        pub_date=entry.get("published", "").strip(),
                        source_url=feed["url"],
                    )
                )
        log.info("Parsed %d items from %d feed(s)", len(items), len(feeds))
        return items

    # --- LLM helpers -------------------------------------------------------

    @staticmethod
    def _extract_json(content: str) -> str:
        content = content.strip()
        if "```json" in content:
            content = content.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in content:
            content = content.split("```", 1)[1].split("```", 1)[0].strip()
        if not content.startswith("{"):
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                content = match.group(0)
        return content

    def parse_with_perplexity(self, items: list[ThreatIntelItem]) -> list[ThreatIntelItem]:
        if not self.perplexity_client:
            log.warning("Perplexity not configured; skipping enrichment")
            return items
        template = load_prompt(self.cfg.prompts_dir, "comprehensive_threat_processor.txt")

        def enhance(item: ThreatIntelItem) -> ThreatIntelItem:
            prompt = template.replace("{item}", json.dumps(item, indent=2, default=str))
            try:
                resp = self.perplexity_client.chat.completions.create(
                    model=self.cfg.perplexity_model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.cfg.openai_temperature,
                )
                content = resp.choices[0].message.content
                if content:
                    parsed = json.loads(self._extract_json(content))
                    if parsed:
                        item.update(parsed)
            except Exception as exc:  # noqa: BLE001 - keep item on any failure
                log.error("Enrichment failed for %r: %s", item.get("title"), exc)
            return item

        enhanced: list[ThreatIntelItem] = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            for future in as_completed(pool.submit(enhance, i) for i in items):
                enhanced.append(future.result())
        log.info("Enriched %d items", len(enhanced))
        return enhanced

    def research_cves(self, items: list[ThreatIntelItem]) -> list[ThreatIntelItem]:
        if not self.perplexity_client:
            log.warning("Perplexity not configured; skipping CVE research")
            return items
        cve_items = [i for i in items if i.get("category") == "CVE"]
        template = load_prompt(self.cfg.prompts_dir, "perplexity_research.txt")
        log.info("Researching %d CVE item(s)", len(cve_items))

        def research(item: ThreatIntelItem) -> ThreatIntelItem:
            cve_ids = item.get("cve_ids", []) or [
                c.get("CVE_ID") for c in item.get("cves", []) if c.get("CVE_ID")
            ]
            if not cve_ids:
                return item
            prompt = fill(
                template,
                title=item["title"],
                description=item["description"],
                cve_ids=", ".join(cve_ids),
                pub_date=item["pub_date"],
            )
            try:
                resp = self.perplexity_client.chat.completions.create(
                    model=self.cfg.perplexity_model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.cfg.openai_temperature,
                )
                content = resp.choices[0].message.content
                if not content:
                    return item
                result = json.loads(self._extract_json(content))
                if result.get("cves"):
                    item["cves"] = result["cves"]
                for field_name in (
                    "affected_systems",
                    "versions_affected",
                    "ioc",
                    "action_items",
                    "research_sources",
                    "latest_updates",
                    "category",
                ):
                    if field_name in result:
                        item[field_name] = result[field_name]
                if not item.get("news_link"):
                    item["news_link"] = item["link"]
            except Exception as exc:  # noqa: BLE001
                log.error("CVE research failed for %r: %s", item.get("title"), exc)
            return item

        researched: list[ThreatIntelItem] = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            for future in as_completed(pool.submit(research, i) for i in cve_items):
                researched.append(future.result())

        by_title = {r["title"]: r for r in researched}
        return [by_title.get(i["title"], i) for i in items]

    def categorize_cves_by_score(self, items: list[ThreatIntelItem]) -> list[ThreatIntelItem]:
        for item in items:
            if item.get("category") != "CVE":
                continue
            cves = item.get("cves", [])
            scores = [parse_cvss(c.get("CVE_Score")) for c in cves]
            scores = [s for s in scores if s is not None]
            max_score = max(scores) if scores else 0.0
            critical = any(str(c.get("CVE_Severity", "")).lower() == "critical" for c in cves)
            item["category"] = (
                "Critical CVE" if (max_score >= 9.0 or critical) else "Non-Critical CVE"
            )
            log.info(
                "Categorized %r as %s (max score %.1f)",
                item["title"], item["category"], max_score,
            )
        return items

    def categorize_news_items(self, news_items: list[dict]) -> dict[str, list[dict]]:
        if not news_items:
            return {}
        if not self.openai_client:
            return {"Security News": news_items}
        prompt = fill(
            load_prompt(self.cfg.prompts_dir, "news_categorization.txt"),
            news_items=json.dumps(news_items, indent=2, default=str),
            item_count=str(len(news_items)),
        )
        try:
            resp = self.openai_client.chat.completions.create(
                model=self.cfg.openai_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.cfg.openai_temperature,
            )
            result = resp.choices[0].message.content
            categories = json.loads(self._extract_json(result))
            categorized: dict[str, list[dict]] = {}
            assigned = set()
            for name, indices in categories.items():
                categorized[name] = [news_items[i] for i in indices if 0 <= i < len(news_items)]
                assigned.update(indices)
            missing = set(range(len(news_items))) - assigned
            if missing:
                categorized.setdefault("Security News", []).extend(news_items[i] for i in missing)
            return categorized
        except Exception as exc:  # noqa: BLE001
            log.error("News categorization failed: %s", exc)
            return {"Security News": news_items}

    def _llm_section(self, prompt: str) -> str | None:
        resp = self.openai_client.chat.completions.create(
            model=self.cfg.openai_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.cfg.openai_temperature,
        )
        content = resp.choices[0].message.content
        if not content:
            return None
        return validate_html_structure(clean_html_content(content))

    def format_emails(self, items: list[ThreatIntelItem]) -> dict[str, str]:
        generation_date = datetime.now().strftime("%Y-%m-%d")
        cve_items = deduplicate_cve_items([i for i in items if "CVE" in (i.get("category") or "")])
        news_items = [i for i in items if i.get("category") == "News"]
        emails: dict[str, str] = {}

        if cve_items and self.openai_client:
            emails["cve"] = self._render_cve_email(cve_items, generation_date)
        if news_items and self.openai_client:
            emails["news"] = self._render_news_email(news_items, generation_date)
        return emails

    def _render_cve_email(self, cve_items: list[ThreatIntelItem], generation_date: str) -> str:
        template = self._read_template("cve_email_template.html", fallback_kind="cve")
        critical = [i for i in cve_items if i.get("category") == "Critical CVE"]
        non_critical = [i for i in cve_items if i.get("category") == "Non-Critical CVE"]
        critical_html = self._batch_sections(critical, "critical_cve_batch.txt")
        non_critical_html = self._batch_sections(non_critical, "non_critical_cve_batch.txt")
        email = template.replace("{{CRITICAL_CVE_ITEMS}}", critical_html)
        email = email.replace("{{NON_CRITICAL_CVE_ITEMS}}", non_critical_html)
        email = email.replace("{{GENERATION_DATE}}", generation_date)
        email = email.replace("{{TOTAL_CVE_COUNT}}", str(len(cve_items)))
        email = email.replace("{{CRITICAL_COUNT}}", str(len(critical)))
        email = email.replace("{{NON_CRITICAL_COUNT}}", str(len(non_critical)))
        return email

    def _render_news_email(self, news_items: list[ThreatIntelItem], generation_date: str) -> str:
        template = self._read_template("news_email_template.html", fallback_kind="news")
        filtered = filter_news_by_date(news_items, self.cfg.news_days_filter)
        if not filtered:
            email = template.replace("{{NEWS_SECTIONS}}", "<p>No recent news items found.</p>")
            email = email.replace("{{GENERATION_DATE}}", generation_date)
            return email.replace("{{TOTAL_NEWS_COUNT}}", "0")
        categorized = self.categorize_news_items(filtered)
        sections = []
        for name, group in categorized.items():
            header = f'<div class="section"><h2 class="section-title">{name}</h2>'
            body = self._batch_sections(group, "news_batch.txt", category_name=name, batch_size=10)
            sections.append(f"{header}\n{body}\n</div>")
        email = template.replace("{{NEWS_SECTIONS}}", "\n\n".join(sections))
        email = email.replace("{{GENERATION_DATE}}", generation_date)
        return email.replace("{{TOTAL_NEWS_COUNT}}", str(len(filtered)))

    def _batch_sections(self, items, prompt_name, category_name=None, batch_size=5) -> str:
        template = load_prompt(self.cfg.prompts_dir, prompt_name)
        sections = []
        for start in range(0, len(items), batch_size):
            batch = items[start : start + batch_size]
            prompt = fill(
                template,
                batch_count=str(len(batch)),
                batch_data=json.dumps(batch, indent=2, default=str),
                **({"category_name": category_name} if category_name else {}),
            )
            try:
                section = self._llm_section(prompt)
                if section:
                    sections.append(section)
            except Exception as exc:  # noqa: BLE001
                log.error("Batch rendering failed (%s): %s", prompt_name, exc)
        return "\n\n".join(sections)

    def _read_template(self, name: str, fallback_kind: str) -> str:
        path = self.cfg.template_path(name)
        if path.exists():
            return path.read_text(encoding="utf-8")
        log.error("Template %s not found; using minimal fallback", name)
        if fallback_kind == "cve":
            return (
                "<html><body><h1>CVE Alerts</h1>"
                "{{CRITICAL_CVE_ITEMS}}{{NON_CRITICAL_CVE_ITEMS}}</body></html>"
            )
        return "<html><body><h1>Security News</h1>{{NEWS_SECTIONS}}</body></html>"

    # --- entry point -------------------------------------------------------

    def run(self, dry_run: bool = False) -> dict[str, str]:
        start = time.time()
        log.info("Starting Threat Intelligence Pipeline%s", " (dry run)" if dry_run else "")
        if not self.openai_client:
            raise RuntimeError("OPENAI_API_KEY is required to run the pipeline")

        feeds = self.fetch_feeds(self.cfg.feed_urls)
        items = self.parse_xml_feeds(feeds)
        if not items:
            log.error("No items parsed; aborting")
            return {}
        items = self.parse_with_perplexity(items)
        items = self.research_cves(items)
        items = self.categorize_cves_by_score(items)
        items = [i for i in items if i.get("category") not in (None, "", "Unknown")]
        emails = self.format_emails(items)

        if dry_run:
            log.info("Dry run: generated %d email(s), not sending", len(emails))
        else:
            if "news" in emails:
                self.email_sender.send_email(
                    f"{self.cfg.email_subject} - Security News", emails["news"]
                )
            if "cve" in emails:
                self.email_sender.send_email(
                    f"{self.cfg.email_subject} - CVE Alerts", emails["cve"]
                )
        log.info("Pipeline completed in %.1fs", time.time() - start)
        return emails
