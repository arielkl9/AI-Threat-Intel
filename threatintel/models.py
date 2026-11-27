"""Data model for a single threat-intelligence item.

``ThreatIntelItem`` behaves as a dict (it is JSON-serialisable and the LLM
prompts receive it as JSON) while exposing attribute access and backward
compatibility between the legacy flat CVE fields (``cve_ids``/``cve_scores``
/``cve_links``/``severities``) and the unified ``cves`` list of dicts.
"""

from __future__ import annotations


class ThreatIntelItem(dict):
    def __init__(
        self,
        title: str,
        description: str,
        link: str,
        pub_date: str,
        category: str | None = None,
        cves: list[dict] | None = None,
        affected_systems: list[str] | None = None,
        ioc: list[str] | None = None,
        action_items: list[str] | None = None,
        source_url: str | None = None,
        versions_affected: list[str] | None = None,
        news_link: str | None = None,
        research_sources: list[str] | None = None,
        latest_updates: str | None = None,
        cve_ids: list[str] | None = None,
        cve_scores: list[str] | None = None,
        cve_links: list[str] | None = None,
        severities: list[str] | None = None,
        cve_score: str | None = None,
        cve_link: str | None = None,
        severity: str | None = None,
    ):
        if cves is None and cve_ids:
            cves = []
            for i, cve_id in enumerate(cve_ids):
                cve_dict = {"CVE_ID": cve_id}
                if cve_scores and i < len(cve_scores):
                    cve_dict["CVE_Score"] = cve_scores[i]
                elif cve_score and i == 0:
                    cve_dict["CVE_Score"] = cve_score
                if cve_links and i < len(cve_links):
                    cve_dict["CVE_Link"] = cve_links[i]
                elif cve_link and i == 0:
                    cve_dict["CVE_Link"] = cve_link
                if severities and i < len(severities):
                    cve_dict["CVE_Severity"] = severities[i]
                elif severity and i == 0:
                    cve_dict["CVE_Severity"] = severity
                cves.append(cve_dict)

        super().__init__(
            title=title,
            description=description,
            link=link,
            pub_date=pub_date,
            category=category,
            cves=cves or [],
            affected_systems=affected_systems,
            ioc=ioc,
            action_items=action_items,
            source_url=source_url,
            versions_affected=versions_affected,
            news_link=news_link,
            research_sources=research_sources,
            latest_updates=latest_updates,
        )

    def __setattr__(self, key, value):
        self[key] = value

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            cves = self.get("cves", [])
            if item == "cve_ids":
                return [c.get("CVE_ID") for c in cves if c.get("CVE_ID")]
            if item == "cve_scores":
                return [c.get("CVE_Score") for c in cves if c.get("CVE_Score")]
            if item == "cve_links":
                return [c.get("CVE_Link") for c in cves if c.get("CVE_Link")]
            if item == "severities":
                return [c.get("CVE_Severity") for c in cves if c.get("CVE_Severity")]
            if item == "cve_score":
                return cves[0].get("CVE_Score") if cves else None
            if item == "cve_link":
                return cves[0].get("CVE_Link") if cves else None
            if item == "severity":
                return cves[0].get("CVE_Severity") if cves else None
            raise AttributeError(
                f"'ThreatIntelItem' object has no attribute '{item}'"
            ) from None
