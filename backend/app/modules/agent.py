"""VendorGuard Autonomous Agent.

Chains the 6 primitives of the platform (OSINT → score → DPDP → contract →
playbook → audit pack) into a single orchestrated flow, streaming progress
over SSE so the UI can render a live 6-step checklist.

Everything here is a thin orchestrator — no new logic, no new dependencies.
The agent *is* the compositional story the pitch talks about: six deterministic
steps chained autonomously, with LLM only in the optional Executive Summary
step. Fully DPDP-auditable because each step's output is written back to the
same SQLite-backed store as a manual scan.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from app.modules import (
    ai_risk,
    contract,
    dpdp,
    events,
    osint,
    playbook,
    store,
    trust_score,
)
from app.schemas import ScanResponse

# Step weights so the UI progress bar is smooth (must sum to 100).
STEPS = [
    ("osint", "Run OSINT fan-out (Shodan/HIBP/crt.sh/VT/DNS/TLS/nuclei)", 30),
    ("score", "Compute Trust Score", 5),
    ("dpdp", "Map findings to DPDP clauses + RAG citations", 15),
    ("contract", "Run Contract Intelligence on attached DPA (optional)", 20),
    ("summary", "Generate Executive Summary (LLM polish if configured)", 10),
    ("playbook", "Build Monday remediation playbook", 10),
    ("audit", "Assemble Audit Bundle ZIP + CERT-In Form-A", 10),
]


def _publish(run_id: str, payload: dict[str, Any]) -> None:
    events.publish("agent", {"run_id": run_id, **payload})


async def run(
    vendor: str,
    contract_text: str | None = None,
    polish_rewrites: bool = False,
) -> dict[str, Any]:
    """Execute the 6-step autonomous onboarding agent.

    Publishes `{step, label, status, progress_pct, duration_ms, summary}` to
    the `agent` SSE channel after each step.
    """
    vendor = vendor.strip().lower()
    run_id = f"agent-{int(time.time() * 1000)}"
    started = time.perf_counter()
    progress = 0
    steps_log: list[dict[str, Any]] = []

    def _log(step_key: str, label: str, weight: int, duration_ms: int, summary: str):
        nonlocal progress
        progress += weight
        row = {
            "step": step_key,
            "label": label,
            "status": "done",
            "progress_pct": progress,
            "duration_ms": duration_ms,
            "summary": summary,
        }
        steps_log.append(row)
        _publish(run_id, row)

    def _start(step_key: str, label: str):
        _publish(run_id, {"step": step_key, "label": label, "status": "running", "progress_pct": progress})

    # ---- 1. OSINT ----
    t = time.perf_counter()
    _start("osint", STEPS[0][1])
    findings = await osint.run_osint(vendor)
    _log("osint", STEPS[0][1], STEPS[0][2], int((time.perf_counter() - t) * 1000),
         f"{len(findings)} findings collected.")

    # ---- 2. Score ----
    t = time.perf_counter()
    _start("score", STEPS[1][1])
    score = trust_score.compute_score(findings)
    _log("score", STEPS[1][1], STEPS[1][2], int((time.perf_counter() - t) * 1000),
         f"Trust {score.score}/100 ({score.band}).")

    # ---- 3. DPDP ----
    t = time.perf_counter()
    _start("dpdp", STEPS[2][1])
    mappings = dpdp.map_findings(findings)
    exposure = dpdp.total_exposure(mappings)
    _log("dpdp", STEPS[2][1], STEPS[2][2], int((time.perf_counter() - t) * 1000),
         f"{len(mappings)} clause mappings, ₹{exposure / 1e7:.0f} Cr exposure.")

    # ---- 4. Contract Intel (optional) ----
    contract_analysis: dict[str, Any] | None = None
    t = time.perf_counter()
    if contract_text and contract_text.strip():
        _start("contract", STEPS[3][1])
        contract_analysis = contract.analyze(contract_text)
        if polish_rewrites:
            try:
                for g in contract_analysis["gaps"]:
                    g["recommended_rewrite"] = await contract.polish_rewrite(
                        g["label"], g["recommended_rewrite"]
                    )
            except Exception:  # noqa: BLE001
                pass
        _log("contract", STEPS[3][1], STEPS[3][2], int((time.perf_counter() - t) * 1000),
             f"{contract_analysis.get('red_count', 0)} red / "
             f"{contract_analysis.get('amber_count', 0)} amber / "
             f"{contract_analysis.get('green_count', 0)} green clauses.")
    else:
        _log("contract", STEPS[3][1], STEPS[3][2], int((time.perf_counter() - t) * 1000),
             "Skipped (no DPA text provided).")

    # ---- 5. Executive summary ----
    t = time.perf_counter()
    _start("summary", STEPS[4][1])
    summary = await ai_risk.summarise(vendor, findings, mappings, exposure)
    _log("summary", STEPS[4][1], STEPS[4][2], int((time.perf_counter() - t) * 1000),
         f"{len(summary)} character summary.")

    # ---- Persist the scan (so /playbook, /audit work) ----
    resp = ScanResponse(
        vendor=vendor,
        scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        duration_ms=int((time.perf_counter() - started) * 1000),
        findings=findings,
        dpdp=mappings,
        ai_summary=summary,
        trust=score,
        total_dpdp_exposure_inr=exposure,
    )
    await store.save_scan(vendor, resp.model_dump())
    events.publish("scans", {"vendor": vendor, "trust": score.model_dump(), "exposure_inr": exposure})

    # ---- 6. Playbook ----
    t = time.perf_counter()
    _start("playbook", STEPS[5][1])
    pb = playbook.build_for(resp.model_dump())
    pb_total = sum(len(pb.get(k) or []) for k in ("next_7_days", "next_30_days", "long_horizon"))
    _log("playbook", STEPS[5][1], STEPS[5][2], int((time.perf_counter() - t) * 1000),
         f"{pb_total} remediation actions generated.")

    # ---- 7. Audit Bundle (just signal — actual ZIP is fetched via /audit/...) ----
    t = time.perf_counter()
    _start("audit", STEPS[6][1])
    await asyncio.sleep(0)  # yield
    _log("audit", STEPS[6][1], STEPS[6][2], int((time.perf_counter() - t) * 1000),
         f"Audit bundle ready at /audit/{vendor}.zip")

    total_ms = int((time.perf_counter() - started) * 1000)
    result = {
        "run_id": run_id,
        "vendor": vendor,
        "total_ms": total_ms,
        "scan": json.loads(resp.model_dump_json()),
        "playbook": pb,
        "contract_analysis": contract_analysis,
        "steps": steps_log,
        "summary_line": (
            f"Onboarded {vendor} in {total_ms}ms. "
            f"Trust {score.score}/100 ({score.band}). "
            f"₹{exposure / 1e7:.0f} Cr DPDP exposure. "
            f"{len(findings)} findings, {len(mappings)} clauses, "
            f"{pb_total} playbook actions."
        ),
    }
    _publish(run_id, {"step": "__done__", "status": "done", "progress_pct": 100, "result": result})
    return result
