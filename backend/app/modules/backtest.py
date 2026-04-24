"""Real-breach back-test harness.

For each famous Indian vendor-mediated breach (AIIMS 2022, BigBasket 2020,
MobiKwik 2021) we ship a reconstructed finding set with what VendorGuard's
rule engine **would have flagged** at the vendor's onboarding. Judges and
auditors can click through to see evidence tied to a real incident, not a
hypothetical.

This is deliberately **public-record-only** — all references are linked; we
never claim insider knowledge. It's a reproducibility and credibility
feature, not a privacy-sensitive one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.modules.dpdp import map_findings, total_exposure
from app.modules.framework import crosswalk_for
from app.modules.rag import retriever
from app.schemas import Finding

_DATA = Path(__file__).parent.parent / "data" / "real_breach_backtests.json"
_RAW = json.loads(_DATA.read_text())
_CASES: list[dict[str, Any]] = _RAW["cases"]
_CASES_BY_ID: dict[str, dict[str, Any]] = {c["id"]: c for c in _CASES}


def list_cases() -> dict[str, Any]:
    return {
        "source": _RAW["source"],
        "note": _RAW["note"],
        "count": len(_CASES),
        "cases": [
            {
                "id": c["id"],
                "label": c["label"],
                "incident_date": c["incident_date"],
                "affected_records_millions": c["affected_records_millions"],
                "trust_score": c["trust_score"],
                "band": c["band"],
                "exposure_inr": c["exposure_inr"],
                "would_have_been_blocked": c["would_have_been_blocked"],
            }
            for c in _CASES
        ],
    }


def _infer_tag(f: dict[str, Any]) -> str:
    """Best-effort evidence tag so `dpdp.map_findings` hits the right clause.

    Tag set must match `dpdp_clauses.json.finding_to_clause` keys exactly.
    """
    title = (f.get("title") or "").lower()
    clause = f.get("clause") or ""
    if "cross-border" in title or "§16" in clause:
        return "cross_border_transfer"
    if "breach corpora" in title or "hibp" in (f.get("source") or "").lower() or "breach history" in title:
        return "leaked_credentials"
    if "breach-notification" in title or "§8(6)" in clause:
        return "breach_history"
    if "retention" in title or "§8(7)" in clause or "erasure" in title:
        return "retention_excess"
    if "sub-processor" in title or "§8(8)" in clause or "records obligation" in title:
        return "no_grievance"
    if "children" in title or "§9" in clause:
        return "childrens_data_unrestricted"
    if "dpo" in title or "§10" in clause or "significant data fiduciary" in title:
        return "no_dpo"
    if "shadow" in title or "subdomain" in title or "crt.sh" in title:
        return "exposed_pii_endpoint"
    if "cve" in title or "tomcat" in title or "apache" in title:
        return "cve_exposure"
    if "mongodb" in title or "s3" in title or "rdp" in title or "encryption" in title:
        return "open_database_port"
    if "best-effort" in title or "safeguards" in title or "§8(5)" in clause:
        return "open_database_port"
    return "open_database_port"


def _enrich_finding(f: dict[str, Any]) -> dict[str, Any]:
    clause = f.get("clause")
    quote = None
    citation = None
    if clause:
        hit = retriever().lookup_clause(clause)
        if hit:
            quote = (hit.get("excerpt") or "")[:400]
            citation = hit.get("citation")
    return {
        **f,
        "rag_quote": quote,
        "rag_citation": citation,
        "crosswalk": crosswalk_for(clause) if clause else None,
    }


def run(case_id: str) -> dict[str, Any] | None:
    case = _CASES_BY_ID.get(case_id)
    if not case:
        return None
    findings_raw = case["what_vendorguard_would_have_flagged"]
    fake_findings: list[Finding] = []
    for i, f in enumerate(findings_raw):
        fake_findings.append(
            Finding(
                id=f"backtest-{case_id}-{i}",
                source=f["source"] if f["source"] not in ("dpa-review",) else "dpdp-rule",
                title=f["title"],
                description=f["detail"],
                severity=f["severity"],
                evidence={"tag": f.get("tag") or _infer_tag(f)},
            )
        )
    mappings = map_findings(fake_findings)
    exposure = total_exposure(mappings)
    enriched_findings = [_enrich_finding(f) for f in findings_raw]
    return {
        "id": case["id"],
        "label": case["label"],
        "incident_date": case["incident_date"],
        "affected_records_millions": case["affected_records_millions"],
        "public_references": case["public_references"],
        "attack_class": case["attack_class"],
        "one_liner": case["one_liner"],
        "vendor_domain": case["vendor_domain"],
        "findings": enriched_findings,
        "dpdp_mappings": [m.model_dump() for m in mappings],
        "trust": {
            "score": case["trust_score"],
            "band": case["band"],
        },
        "exposure_inr_rule_engine": exposure,
        "exposure_inr_case_ceiling": case["exposure_inr"],
        "would_have_been_blocked": case["would_have_been_blocked"],
        "outcome_narrative": case["outcome_narrative"],
        "disclaimer": (
            "Reconstruction from public post-incident reporting only. "
            "VendorGuard AI does not claim insider knowledge of these incidents; "
            "see `public_references` for the primary sources each finding is grounded in."
        ),
    }
