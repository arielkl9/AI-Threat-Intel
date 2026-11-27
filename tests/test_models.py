"""Tests for the ThreatIntelItem compatibility shim."""

from __future__ import annotations

from threatintel.models import ThreatIntelItem


def test_legacy_fields_build_cves():
    item = ThreatIntelItem(
        title="t", description="d", link="l", pub_date="p",
        cve_ids=["CVE-2024-1", "CVE-2024-2"],
        cve_scores=["9.8", "7.5"],
        cve_links=["a", "b"],
        severities=["Critical", "High"],
    )
    assert len(item["cves"]) == 2
    assert item["cves"][0] == {
        "CVE_ID": "CVE-2024-1", "CVE_Score": "9.8", "CVE_Link": "a", "CVE_Severity": "Critical",
    }


def test_derived_accessors_from_cves():
    item = ThreatIntelItem(
        title="t", description="d", link="l", pub_date="p",
        cves=[{"CVE_ID": "CVE-2024-9", "CVE_Score": "6.1", "CVE_Severity": "Medium"}],
    )
    assert item.cve_ids == ["CVE-2024-9"]
    assert item.cve_score == "6.1"
    assert item.severity == "Medium"


def test_unknown_attribute_raises():
    item = ThreatIntelItem(title="t", description="d", link="l", pub_date="p")
    try:
        _ = item.does_not_exist
    except AttributeError:
        return
    raise AssertionError("expected AttributeError")
