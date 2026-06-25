"""
Red-team runner for GuardrailProbe.

Fires AttackProbes from probes.py against one or more backends, collects
structured reports, and detects regressions between runs.

Usage::

    from guardrailprobe.runner import RedTeamRunner
    from guardrailprobe.probes import ProbeLibrary, AttackCategory
    from guardrailprobe._types import GuardrailBackend

    runner = RedTeamRunner()

    # Single-backend sweep
    report = runner.run_against_backend(
        GuardrailBackend.GUARDRAILS_AI,
        categories=[AttackCategory.PROMPT_INJECTION],
        severity_filter="critical",
    )
    print(f"Pass rate: {report.pass_rate:.1%}")

    # Multi-backend comparison
    cmp = runner.compare_backends(
        [GuardrailBackend.GUARDRAILS_AI, GuardrailBackend.NEMO],
    )
    print(cmp.best_overall, cmp.category_winners)

    # Regression detection
    diff = runner.run_regression(
        baseline_report_id=report.run_id,
        backend=GuardrailBackend.GUARDRAILS_AI,
    )
    for reg in diff["regressions"]:
        print("[RED] regression:", reg["probe_id"], reg["description"])
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as _FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from guardrailprobe._types import ActionType, AdapterStatus, GuardrailBackend, ProbeResponse
from guardrailprobe.adapters import REGISTRY
from guardrailprobe.probes import AttackCategory, AttackProbe, ProbeLibrary

_BACKEND_TIMEOUT_SECS = 120

logger = logging.getLogger("RedTeamRunner")

MIN_COVERAGE_PCT: float = 50.0

BACKEND_SCOPE: Dict[str, Dict[str, Any]] = {
    "nemo": {
        "type": "general",
        "label": "General LLM Safety",
    },
    "guardrails_ai": {
        "type": "specialized",
        "label": "Validation Framework",
        "note": "requires validators; compare within PII/content use cases",
    },
    "presidio": {
        "type": "specialized",
        "label": "PII Detection",
        "note": "designed for PII and credential detection (LLM06) only",
    },
    "lakera": {
        "type": "general",
        "label": "Prompt Security",
    },
    "custom_http": {
        "type": "general",
        "label": "Content Safety",
    },
    "openai_moderation": {
        "type": "specialized",
        "label": "Content Moderation",
        "note": "content policy classification only; subject to rate limits",
    },
    "azure_content_safety": {
        "type": "general",
        "label": "Content Safety",
    },
    "azure_prompt_shields": {
        "type": "specialized",
        "label": "Prompt Injection Guard",
        "note": "designed specifically for prompt injection detection",
    },
    "aws_bedrock": {
        "type": "general",
        "label": "General Guardrails",
    },
    "llama_firewall": {
        "type": "general",
        "label": "Prompt Injection Guard",
    },
    "llm_guard": {
        "type": "general",
        "label": "Input Safety Scanner",
    },
}


# ── Result dataclasses ────────────────────────────────────────────────────────


@dataclass
class ProbeResult:
    """Outcome of firing a single AttackProbe against one backend."""

    probe: AttackProbe
    backend: GuardrailBackend
    actual_action: Optional[ActionType]
    expected_action: ActionType
    passed: Optional[bool]
    latency_ms: float
    timestamp: str
    raw_response: ProbeResponse
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class RedTeamReport:
    """Aggregated result of running a probe set against a single backend."""

    backend: GuardrailBackend
    run_id: str
    timestamp: str
    total_probes: int
    passed: int
    failed: int
    pass_rate: float
    results_by_category: Dict[str, Dict[str, Any]]
    results_by_severity: Dict[str, Dict[str, Any]]
    average_latency_ms: float
    probe_results: List[ProbeResult] = field(default_factory=list)
    skipped_count: int = 0
    skipped_backends: Dict[str, str] = field(default_factory=dict)
    coverage_pct: float = 0.0


@dataclass
class ComparisonReport:
    """Side-by-side comparison of multiple backends on the same probe set."""

    run_id: str
    timestamp: str
    backends_tested: List[GuardrailBackend]
    reports: Dict[str, RedTeamReport]
    best_overall: str
    worst_overall: str
    category_winners: Dict[str, Dict[str, Any]]
    summary_table: List[Dict[str, Any]]
    skipped_backends: Dict[str, str] = field(default_factory=dict)


# ── Runner ────────────────────────────────────────────────────────────────────


class RedTeamRunner:
    """Orchestrates red-team probing of guardrail backends via the adapter registry."""

    def __init__(self) -> None:
        self._reports: Dict[str, RedTeamReport] = {}
        self._comparison_reports: Dict[str, ComparisonReport] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def run_against_backend(
        self,
        backend: GuardrailBackend,
        probes: Optional[List[AttackProbe]] = None,
        categories: Optional[List[AttackCategory]] = None,
        severity_filter: Optional[str] = None,
    ) -> RedTeamReport:
        """Fire a filtered probe set against *backend* and return a report."""
        run_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        active_probes = _filter_probes(probes, categories, severity_filter)

        adapter = REGISTRY.get(backend.value)
        if adapter is not None and not adapter.check_credentials():
            skip_reason = "MISSING_CREDENTIALS"
            now = datetime.now(timezone.utc).isoformat()
            probe_results = [
                ProbeResult(
                    probe=probe,
                    backend=backend,
                    actual_action=None,
                    expected_action=probe.expected_action,
                    passed=None,
                    latency_ms=0.0,
                    timestamp=now,
                    raw_response=ProbeResponse(
                        action=ActionType.SKIPPED,
                        latency_ms=0.0,
                        raw_response={"skipped": True, "reason": skip_reason},
                        backend=backend.value,
                        status=AdapterStatus.NO_API_KEY,
                    ),
                    skipped=True,
                    skip_reason=skip_reason,
                )
                for probe in active_probes
            ]
            report = _build_report(
                backend, run_id, timestamp, probe_results,
                skipped_backends={backend.value: skip_reason},
            )
            self._reports[run_id] = report
            logger.info(
                "Red-team run %s SKIPPED | backend=%s | reason=%s",
                run_id, backend.value, skip_reason,
            )
            return report

        logger.info(
            "Red-team run %s starting | backend=%s | probes=%d",
            run_id, backend.value, len(active_probes),
        )

        probe_results = [
            self._run_one(probe, backend)
            for probe in active_probes
        ]

        report = _build_report(backend, run_id, timestamp, probe_results)
        self._reports[run_id] = report

        logger.info(
            "Red-team run %s complete | pass_rate=%.1f%% (%d/%d) | avg_latency=%.1f ms",
            run_id, report.pass_rate * 100, report.passed,
            report.total_probes, report.average_latency_ms,
        )
        return report

    def compare_backends(
        self,
        backends: List[GuardrailBackend],
        probes: Optional[List[AttackProbe]] = None,
        categories: Optional[List[AttackCategory]] = None,
    ) -> ComparisonReport:
        """Run the same probe set against every backend and compare results."""
        if not backends:
            raise ValueError("backends must contain at least one GuardrailBackend.")

        run_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        active_probes = probes or []

        def _run(backend: GuardrailBackend) -> RedTeamReport:
            return self.run_against_backend(backend, probes=probes, categories=categories)

        reports: Dict[str, RedTeamReport] = {}
        with ThreadPoolExecutor(max_workers=len(backends)) as pool:
            futures: Dict[str, Future] = {
                b.value: pool.submit(_run, b) for b in backends
            }
            for bval, fut in futures.items():
                try:
                    reports[bval] = fut.result(timeout=_BACKEND_TIMEOUT_SECS)
                except _FuturesTimeout:
                    logger.warning(
                        "Backend %s timed out after %ds — marking SKIPPED",
                        bval, _BACKEND_TIMEOUT_SECS,
                    )
                    reports[bval] = _build_timeout_report(
                        GuardrailBackend(bval), active_probes, timestamp
                    )
                except Exception as exc:
                    logger.error("Backend %s raised %s — marking SKIPPED", bval, exc)
                    reports[bval] = _build_timeout_report(
                        GuardrailBackend(bval), active_probes, timestamp, reason=str(exc)
                    )

        custom_http_no_url = not os.getenv("GA_GUARD_API_URL", "").strip()
        eligible = {
            k: v for k, v in reports.items()
            if v.total_probes > 0
            and v.coverage_pct >= MIN_COVERAGE_PCT
            and BACKEND_SCOPE.get(k, {}).get("type") == "general"
            and not (k == "custom_http" and custom_http_no_url)
        }
        ranked = eligible or {k: v for k, v in reports.items() if v.total_probes > 0} or reports
        best_overall = max(ranked, key=lambda k: ranked[k].pass_rate)
        worst_overall = min(ranked, key=lambda k: ranked[k].pass_rate)

        all_skipped: Dict[str, str] = {}
        for r in reports.values():
            all_skipped.update(r.skipped_backends)

        comparison = ComparisonReport(
            run_id=run_id,
            timestamp=timestamp,
            backends_tested=list(backends),
            reports=reports,
            best_overall=best_overall,
            worst_overall=worst_overall,
            category_winners=_compute_category_winners(reports),
            summary_table=_build_summary_table(reports),
            skipped_backends=all_skipped,
        )
        self._comparison_reports[run_id] = comparison
        return comparison

    def run_regression(
        self,
        baseline_report_id: str,
        backend: GuardrailBackend,
        probes: Optional[List[AttackProbe]] = None,
        categories: Optional[List[AttackCategory]] = None,
        severity_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compare a fresh run against a stored baseline report."""
        if baseline_report_id not in self._reports:
            raise KeyError(
                f"No stored report with run_id={baseline_report_id!r}. "
                f"Known IDs: {list(self._reports)}"
            )

        baseline = self._reports[baseline_report_id]
        current = self.run_against_backend(
            backend,
            probes=probes,
            categories=categories,
            severity_filter=severity_filter,
        )

        baseline_by_id: Dict[str, ProbeResult] = {
            pr.probe.id: pr for pr in baseline.probe_results
        }
        current_by_id: Dict[str, ProbeResult] = {
            pr.probe.id: pr for pr in current.probe_results
        }

        regressions: List[Dict[str, Any]] = []
        improvements: List[Dict[str, Any]] = []
        stable_pass = 0
        stable_fail = 0

        shared_ids: Set[str] = set(baseline_by_id) & set(current_by_id)
        for probe_id in sorted(shared_ids):
            b = baseline_by_id[probe_id]
            c = current_by_id[probe_id]

            if b.passed and not c.passed:
                regressions.append(_diff_row(b, c, flag="RED"))
            elif not b.passed and c.passed:
                improvements.append(_diff_row(b, c, flag="GREEN"))
            elif c.passed:
                stable_pass += 1
            else:
                stable_fail += 1

        delta = current.pass_rate - baseline.pass_rate
        return {
            "run_id": current.run_id,
            "baseline_run_id": baseline_report_id,
            "backend": backend.value,
            "regressions": regressions,
            "improvements": improvements,
            "stable_pass": stable_pass,
            "stable_fail": stable_fail,
            "total_compared": len(shared_ids),
            "current_pass_rate": current.pass_rate,
            "baseline_pass_rate": baseline.pass_rate,
            "delta_pass_rate": round(delta, 4),
        }

    # ── Report accessors ──────────────────────────────────────────────────────

    def get_report(self, run_id: str) -> Optional[RedTeamReport]:
        return self._reports.get(run_id)

    def get_comparison_report(self, run_id: str) -> Optional[ComparisonReport]:
        return self._comparison_reports.get(run_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        return [
            {
                "run_id": r.run_id,
                "backend": r.backend.value,
                "timestamp": r.timestamp,
                "total_probes": r.total_probes,
                "passed": r.passed,
                "failed": r.failed,
                "pass_rate": r.pass_rate,
                "average_latency_ms": r.average_latency_ms,
            }
            for r in self._reports.values()
        ]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run_one(
        self,
        probe: AttackProbe,
        backend: GuardrailBackend,
    ) -> ProbeResult:
        """Fire a single probe through the adapter registry."""
        adapter = REGISTRY.get(backend.value)
        t0 = time.perf_counter()
        try:
            resp: ProbeResponse = adapter.run_probe(probe.payload)
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1_000.0
            logger.warning("Probe %s raised %s: %s", probe.id, type(exc).__name__, exc)
            resp = ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=round(latency_ms, 2),
                raw_response={"error": str(exc)},
                backend=backend.value,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        actual_action = resp.action
        is_skipped = actual_action == ActionType.SKIPPED
        passed = (not is_skipped) and (actual_action == probe.expected_action)

        return ProbeResult(
            probe=probe,
            backend=backend,
            actual_action=actual_action,
            expected_action=probe.expected_action,
            passed=passed,
            latency_ms=round(resp.latency_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_response=resp,
            skipped=is_skipped,
        )


# ── Module-level helpers ──────────────────────────────────────────────────────


def _filter_probes(
    probes: Optional[List[AttackProbe]],
    categories: Optional[List[AttackCategory]],
    severity_filter: Optional[str],
) -> List[AttackProbe]:
    active = list(probes) if probes is not None else ProbeLibrary().all_probes()
    if categories:
        cat_set = set(categories)
        active = [p for p in active if p.category in cat_set]
    if severity_filter:
        active = [p for p in active if p.severity == severity_filter]
    return active


def _build_report(
    backend: GuardrailBackend,
    run_id: str,
    timestamp: str,
    probe_results: List[ProbeResult],
    skipped_backends: Optional[Dict[str, str]] = None,
) -> RedTeamReport:
    n_skipped = sum(1 for pr in probe_results if pr.skipped)
    active = [pr for pr in probe_results if not pr.skipped]
    total = len(active)
    n_passed = sum(1 for pr in active if pr.passed)
    n_failed = total - n_passed
    pass_rate = n_passed / total if total else 0.0
    avg_latency = sum(pr.latency_ms for pr in active) / total if total else 0.0
    total_possible = len(probe_results)
    coverage_pct = round(total / total_possible * 100, 1) if total_possible else 0.0

    by_category: Dict[str, Dict[str, Any]] = {}
    for pr in active:
        ref = pr.probe.owasp_ref
        b = by_category.setdefault(ref, {"total": 0, "passed": 0, "failed": 0})
        b["total"] += 1
        if pr.passed:
            b["passed"] += 1
        else:
            b["failed"] += 1
    for stats in by_category.values():
        stats["pass_rate"] = round(
            stats["passed"] / stats["total"] if stats["total"] else 0.0, 4
        )

    by_severity: Dict[str, Dict[str, Any]] = {}
    for pr in active:
        sev = pr.probe.severity
        b = by_severity.setdefault(sev, {"total": 0, "passed": 0, "failed": 0})
        b["total"] += 1
        if pr.passed:
            b["passed"] += 1
        else:
            b["failed"] += 1
    for stats in by_severity.values():
        stats["pass_rate"] = round(
            stats["passed"] / stats["total"] if stats["total"] else 0.0, 4
        )

    return RedTeamReport(
        backend=backend,
        run_id=run_id,
        timestamp=timestamp,
        total_probes=total,
        passed=n_passed,
        failed=n_failed,
        pass_rate=round(pass_rate, 4),
        results_by_category=by_category,
        results_by_severity=by_severity,
        average_latency_ms=round(avg_latency, 2),
        probe_results=probe_results,
        skipped_count=n_skipped,
        skipped_backends=skipped_backends or {},
        coverage_pct=coverage_pct,
    )


def _build_timeout_report(
    backend: GuardrailBackend,
    probes: List[AttackProbe],
    timestamp: str,
    reason: str = "TIMEOUT",
) -> RedTeamReport:
    now = datetime.now(timezone.utc).isoformat()
    probe_results = [
        ProbeResult(
            probe=probe,
            backend=backend,
            actual_action=None,
            expected_action=probe.expected_action,
            passed=None,
            latency_ms=0.0,
            timestamp=now,
            raw_response=ProbeResponse(
                action=ActionType.SKIPPED,
                latency_ms=0.0,
                raw_response={"skipped": True, "reason": reason},
                backend=backend.value,
                status=AdapterStatus.NO_API_KEY,
            ),
            skipped=True,
            skip_reason=reason,
        )
        for probe in probes
    ]
    return _build_report(
        backend, str(uuid4()), timestamp, probe_results,
        skipped_backends={backend.value: reason},
    )


def _compute_category_winners(
    reports: Dict[str, RedTeamReport],
) -> Dict[str, Dict[str, Any]]:
    """For each OWASP ref, return winner info with tie-breaking by latency."""
    all_refs: Set[str] = set()
    for r in reports.values():
        all_refs.update(r.results_by_category)

    winners: Dict[str, Dict[str, Any]] = {}
    for ref in all_refs:
        candidates = [
            (b, r.results_by_category[ref]["pass_rate"], r.average_latency_ms or 0.0)
            for b, r in reports.items()
            if ref in r.results_by_category
        ]
        if not candidates:
            continue
        best_score = max(c[1] for c in candidates)
        tied = [(b, score, lat) for b, score, lat in candidates if score == best_score]
        if len(tied) == 1:
            winner_b, winner_score, winner_lat = tied[0]
            winners[ref] = {
                "winner": winner_b,
                "winner_score": round(winner_score * 100, 1),
                "winner_latency_ms": round(winner_lat),
                "tied_backends": [winner_b],
                "tiebreaker": None,
            }
        else:
            winner_b, winner_score, winner_lat = min(tied, key=lambda t: t[2])
            winners[ref] = {
                "winner": winner_b,
                "winner_score": round(winner_score * 100, 1),
                "winner_latency_ms": round(winner_lat),
                "tied_backends": [b for b, _, _ in tied],
                "tiebreaker": "latency",
            }
    return winners


def _build_summary_table(
    reports: Dict[str, RedTeamReport],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for backend_val, report in reports.items():
        for ref, stats in report.results_by_category.items():
            rows.append(
                {
                    "backend": backend_val,
                    "owasp_ref": ref,
                    "total": stats["total"],
                    "passed": stats["passed"],
                    "failed": stats["failed"],
                    "pass_rate": stats["pass_rate"],
                    "average_latency_ms": report.average_latency_ms,
                }
            )
    rows.sort(key=lambda r: (r["owasp_ref"], r["backend"]))
    return rows


def _diff_row(
    baseline: ProbeResult,
    current: ProbeResult,
    flag: str,
) -> Dict[str, Any]:
    return {
        "flag": flag,
        "probe_id": baseline.probe.id,
        "owasp_ref": baseline.probe.owasp_ref,
        "category": baseline.probe.category.value,
        "severity": baseline.probe.severity,
        "description": baseline.probe.description,
        "tags": baseline.probe.tags,
        "baseline_action": baseline.actual_action.value if baseline.actual_action else "skipped",
        "current_action": current.actual_action.value if current.actual_action else "skipped",
        "expected_action": baseline.probe.expected_action.value,
        "baseline_latency_ms": baseline.latency_ms,
        "current_latency_ms": current.latency_ms,
        "latency_delta_ms": round(current.latency_ms - baseline.latency_ms, 2),
    }
