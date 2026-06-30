"""
Monthly OWASP LLM Top 10 guardrail benchmark report generator.

Detects reachable backends via the adapter registry, runs the full probe
library against each one, and writes JSON, Markdown, and a signed PDF.

Usage::

    from guardrailprobe.report import BenchmarkRunner
    runner = BenchmarkRunner()
    arts = runner.generate_monthly_benchmark(year=2026, month=6)
    print(arts.json_path, arts.pdf_path)

CLI equivalent::

    guardrailprobe run --year 2026 --month 6 --output-dir ./benchmarks
"""

from __future__ import annotations

import calendar
import importlib.metadata
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardrailprobe._types import GuardrailBackend
from guardrailprobe.probes import ProbeLibrary
from guardrailprobe.runner import ComparisonReport, RedTeamRunner

logger = logging.getLogger(__name__)

try:
    PROBE_LIBRARY_VERSION = importlib.metadata.version("guardrailprobe")
except importlib.metadata.PackageNotFoundError:
    PROBE_LIBRARY_VERSION = "unknown"
_BACKEND_CHECK_TIMEOUT = 5

REASON_UNAVAILABLE         = "UNAVAILABLE"
REASON_PENDING_LLM         = "PENDING_LLM_CREDITS"
REASON_TIMEOUT             = "TIMEOUT"
REASON_CUSTOM_ENDPOINT     = "CUSTOM_ENDPOINT_NOT_CONFIGURED"


BENCHMARK_TEMPLATE = """\
# GuardrailProbe Benchmark — {MONTH} {YEAR}
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** {BEST_OVERALL_BACKEND} ({BEST_OVERALL_SCORE}% overall)
- **Best accuracy/latency ratio:** {RATIO_WINNER}
- **Biggest improvement vs last month:** {IMPROVEMENT_BACKEND} +{IMPROVEMENT_DELTA}%
- **Biggest regression vs last month:** {REGRESSION_BACKEND} -{REGRESSION_DELTA}%
- **Backends tested:** {BACKENDS_TESTED_COUNT}
- **Backends skipped:** {BACKENDS_SKIPPED_COUNT}
- **Total probes run:** {TOTAL_PROBES}
- **Report generated:** {GENERATED_AT}
- **Run ID:** {RUN_ID}

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
{OVERALL_TABLE_ROWS}

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | {LLM01_WINNER} | {LLM01_SCORE}% | {LLM01_SECOND} | {LLM01_SECOND_SCORE}% |
| LLM02 | Insecure Output | {LLM02_WINNER} | {LLM02_SCORE}% | {LLM02_SECOND} | {LLM02_SECOND_SCORE}% |
| LLM03 | Training Data Poisoning | {LLM03_WINNER} | {LLM03_SCORE}% | {LLM03_SECOND} | {LLM03_SECOND_SCORE}% |
| LLM04 | Model DoS | {LLM04_WINNER} | {LLM04_SCORE}% | {LLM04_SECOND} | {LLM04_SECOND_SCORE}% |
| LLM05 | Supply Chain | {LLM05_WINNER} | {LLM05_SCORE}% | {LLM05_SECOND} | {LLM05_SECOND_SCORE}% |
| LLM06 | Sensitive Info Disclosure | {LLM06_WINNER} | {LLM06_SCORE}% | {LLM06_SECOND} | {LLM06_SECOND_SCORE}% |
| LLM07 | Insecure Plugin | {LLM07_WINNER} | {LLM07_SCORE}% | {LLM07_SECOND} | {LLM07_SECOND_SCORE}% |
| LLM08 | Excessive Agency | {LLM08_WINNER} | {LLM08_SCORE}% | {LLM08_SECOND} | {LLM08_SECOND_SCORE}% |
| LLM09 | Overreliance | {LLM09_WINNER} | {LLM09_SCORE}% | {LLM09_SECOND} | {LLM09_SECOND_SCORE}% |
| LLM10 | Model Theft | {LLM10_WINNER} | {LLM10_SCORE}% | {LLM10_SECOND} | {LLM10_SECOND_SCORE}% |

---

## Content Moderation Results

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
{CONTENT_MODERATION_TABLE_ROWS}

---

## Backend Capability Matrix

| Backend | Prompt Injection | Jailbreak | Content Moderation | PII Detection | Agentic Safety |
|---------|:---------------:|:---------:|:------------------:|:-------------:|:--------------:|
| NeMo Guardrails | ✓ Primary | ✓ | ✗ | ✗ | ✓ |
| GuardrailsAI | ✓ | ✓ | ✗ | ✓ | ✗ |
| Presidio | ✗ | ✗ | ✗ | ✓ Primary | ✗ |
| Lakera Guard | ✓ Primary | ✓ | ✗ | ✗ | ✗ |
| Custom HTTP | ✓ | ✓ | ✗ | ✗ | ✗ |
| OpenAI Moderation | ✗ | ✓ | ✓ Primary | ✗ | ✗ |
| Azure Content Safety | ✗ | ✗ | ✓ Primary | ✗ | ✗ |
| Azure Prompt Shields | ✓ Primary | ✓ | ✗ | ✗ | ✗ |
| AWS Bedrock | ✓ | ✓ | ✓ | ✗ | ✗ |
| Llama Firewall | ✓ Primary | ✓ | ✗ | ✗ | ✗ |
| LLM Guard | ✓ | ✓ | ✓ | ✓ | ✗ |

> ✓ Primary = core strength, ✓ = supported, ✗ = not designed for this

---

## Accuracy vs Latency Tradeoff

| Backend | Overall % | Avg Latency | Latency Category | Recommended For |
|---------|:---------:|:-----------:|:----------------:|-----------------|
{LATENCY_TABLE_ROWS}

---

## Notable Bypasses

{NOTABLE_BYPASSES_LIST}

---

## Backends Skipped This Month

| Backend | Reason | Expected In |
|---------|--------|-------------|
{SKIPPED_BACKENDS_TABLE}

---

## Month-over-Month Changes

{DELTA_SECTION}

---

## How to Reproduce

```bash
pip install guardrailprobe
guardrailprobe run --year {YEAR} --month {MONTH_NUM}
```

Full guide: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

*GuardrailProbe v{VERSION} — independent, open-source, not affiliated with any tested vendor.*
"""


# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class BenchmarkArtifacts:
    """Paths and metadata for one completed benchmark run."""

    year: int
    month: int
    run_id: str
    pdf_path: Optional[str]
    json_path: str
    markdown_path: str
    comparison_report: Optional[ComparisonReport]
    delta: Optional[Dict[str, Any]]
    backends_tested: List[str] = field(default_factory=list)
    backends_skipped: Dict[str, str] = field(default_factory=dict)
    probe_count: int = 0
    generated_at: Optional[datetime] = None


# ── Serialisation helpers ─────────────────────────────────────────────────────


def _enum_safe(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _enum_safe(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_enum_safe(i) for i in v]
    if hasattr(v, "value"):
        return v.value
    return v


def _serialise_comparison(report: ComparisonReport) -> Dict[str, Any]:
    backend_summaries: Dict[str, Any] = {}
    for bname, r in report.reports.items():
        backend_summaries[bname] = {
            "pass_rate": r.pass_rate,
            "passed": r.passed,
            "failed": r.failed,
            "total_probes": r.total_probes,
            "average_latency_ms": round(r.average_latency_ms, 2),
            "results_by_category": r.results_by_category,
            "results_by_severity": r.results_by_severity,
        }
    return {
        "run_id": report.run_id,
        "timestamp": report.timestamp,
        "backends_tested": [b.value for b in report.backends_tested],
        "best_overall": report.best_overall,
        "worst_overall": report.worst_overall,
        "category_winners": report.category_winners,
        "summary_table": _enum_safe(report.summary_table),
        "backend_summaries": backend_summaries,
    }


# ── BenchmarkRunner ───────────────────────────────────────────────────────────


class BenchmarkRunner:
    """Orchestrates monthly benchmark generation.

    Detects which backends are reachable, runs the full probe suite,
    computes month-over-month delta if prior data exists, and writes
    JSON, Markdown, and (best-effort) signed PDF artifacts.
    """

    def __init__(self) -> None:
        self._runner  = RedTeamRunner()
        self._library = ProbeLibrary()

        self._default_output = (
            Path("/app/docs/benchmarks")
            if Path("/app").is_dir()
            else Path("./docs/benchmarks")
        )
        self._docs_index = Path("docs/latest_index.json")

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_monthly_benchmark(
        self,
        year: int,
        month: int,
        backends: Optional[List[GuardrailBackend]] = None,
        dry_run: bool = False,
        output_dir: Optional[Path] = None,
        progress_cb=None,
    ) -> BenchmarkArtifacts:
        """Run all probes against all backends and write artifacts."""
        out_dir = Path(output_dir) if output_dir else self._default_output
        out_dir.mkdir(parents=True, exist_ok=True)

        all_backends = backends or list(GuardrailBackend)
        now = datetime.now(timezone.utc)
        logger.info(
            "Benchmark run (%04d-%02d)  backends=%s  dry_run=%s",
            year, month, [b.value for b in all_backends], dry_run,
        )

        comparison = self._runner.compare_backends(backends=all_backends, progress_cb=progress_cb)

        backends_tested = [
            b.value for b in comparison.backends_tested
            if b.value not in comparison.skipped_backends
        ]
        backends_skipped = dict(comparison.skipped_backends)
        probe_count = sum(r.total_probes for r in comparison.reports.values())

        if not backends_tested and not dry_run:
            raise RuntimeError(
                "No backends returned results — all were skipped. "
                f"Skipped: {list(backends_skipped.keys())}. "
                "Pass dry_run=True to proceed anyway."
            )

        stem = f"benchmark_{year:04d}_{month:02d}"
        artifacts = BenchmarkArtifacts(
            year=year,
            month=month,
            run_id=comparison.run_id,
            pdf_path=None,
            json_path=str(out_dir / f"{stem}.json"),
            markdown_path=str(out_dir / f"{stem}.md"),
            comparison_report=comparison,
            delta=None,
            backends_tested=backends_tested,
            backends_skipped=backends_skipped,
            probe_count=probe_count,
            generated_at=now,
        )

        prior_path = out_dir / _prior_month_filename(year, month)
        if prior_path.exists():
            try:
                artifacts.delta = self._compute_delta(comparison, year, month, out_dir)
            except Exception as exc:
                logger.warning("Month-over-month delta failed: %s", exc)

        self._generate_artifacts(artifacts, comparison, artifacts.delta)
        self._update_docs_index(artifacts)
        logger.info(
            "Done — JSON: %s  MD: %s  PDF: %s",
            artifacts.json_path,
            artifacts.markdown_path,
            artifacts.pdf_path or "(skipped)",
        )
        return artifacts

    def generate_from_comparison(
        self,
        comparison: ComparisonReport,
        year: int,
        month: int,
        output_dir: Optional[Path] = None,
    ) -> BenchmarkArtifacts:
        """Write JSON/MD/PDF for an already-completed ComparisonReport."""
        out_dir = Path(output_dir) if output_dir else self._default_output
        out_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)

        backends_tested = [
            b.value for b in comparison.backends_tested
            if b.value not in comparison.skipped_backends
        ]
        backends_skipped = dict(comparison.skipped_backends)
        probe_count = sum(r.total_probes for r in comparison.reports.values())

        stem = f"benchmark_{year:04d}_{month:02d}"
        artifacts = BenchmarkArtifacts(
            year=year,
            month=month,
            run_id=comparison.run_id,
            pdf_path=None,
            json_path=str(out_dir / f"{stem}.json"),
            markdown_path=str(out_dir / f"{stem}.md"),
            comparison_report=comparison,
            delta=None,
            backends_tested=backends_tested,
            backends_skipped=backends_skipped,
            probe_count=probe_count,
            generated_at=now,
        )

        prior_path = out_dir / _prior_month_filename(year, month)
        if prior_path.exists():
            try:
                artifacts.delta = self._compute_delta(comparison, year, month, out_dir)
            except Exception as exc:
                logger.warning("Month-over-month delta failed: %s", exc)

        self._generate_artifacts(artifacts, comparison, artifacts.delta)
        self._update_docs_index(artifacts)
        return artifacts

    def get_latest_benchmark(self, output_dir: Optional[Path] = None) -> Optional[Dict]:
        out_dir = Path(output_dir) if output_dir else self._default_output
        candidates = sorted(out_dir.glob("benchmark_*.json"))
        if not candidates:
            return None
        with open(candidates[-1]) as fh:
            return json.load(fh)

    def list_all_benchmarks(self, output_dir: Optional[Path] = None) -> List[Dict]:
        out_dir = Path(output_dir) if output_dir else self._default_output
        result = []
        for path in sorted(out_dir.glob("benchmark_*.json")):
            try:
                with open(path) as fh:
                    data = json.load(fh)
                result.append(data.get("metadata", {}))
            except Exception:
                pass
        return result

    # ── Month-over-month delta ────────────────────────────────────────────────

    def _compute_delta(
        self,
        current: ComparisonReport,
        year: int,
        month: int,
        out_dir: Path,
    ) -> Optional[Dict[str, Any]]:
        prior_path = out_dir / _prior_month_filename(year, month)
        if not prior_path.exists():
            return None
        try:
            prior_data: Dict[str, Any] = json.loads(prior_path.read_text())
        except Exception:
            return None

        prior_summaries: Dict[str, Any] = (
            prior_data.get("results", {}).get("backend_summaries", {})
        )
        prior_meta: Dict[str, Any] = prior_data.get("metadata", {})
        prior_backends: set = set(prior_meta.get("backends_tested", []))
        prior_probe_count: int = prior_meta.get("probe_count", 0)

        active_backends = {
            b.value for b in current.backends_tested
            if b.value not in current.skipped_backends
        }

        per_backend: Dict[str, Dict[str, Any]] = {}
        improvements: List[Dict[str, Any]] = []
        regressions: List[Dict[str, Any]] = []

        for bname in sorted(active_backends):
            r = current.reports.get(bname)
            if not r:
                continue
            current_pct = round(r.pass_rate * 100, 2)
            prior_rec = prior_summaries.get(bname, {})
            prior_pct_raw = prior_rec.get("pass_rate")

            if prior_pct_raw is not None:
                prior_pct_f: float = round(float(prior_pct_raw) * 100, 2)
                prior_pct: Optional[float] = prior_pct_f
                delta_pct = round(current_pct - prior_pct_f, 2)
                if delta_pct >= 5:
                    status = "improvement"
                    improvements.append({"backend": bname, "delta": delta_pct})
                elif delta_pct <= -5:
                    status = "regression"
                    regressions.append({"backend": bname, "delta": delta_pct})
                else:
                    status = "stable"
            else:
                prior_pct = None
                delta_pct = 0.0
                status = "new"

            per_backend[bname] = {
                "delta": delta_pct,
                "current": current_pct,
                "prior": prior_pct,
                "status": status,
            }

        improvements.sort(key=lambda x: x["delta"], reverse=True)
        regressions.sort(key=lambda x: x["delta"])

        current_probe_count = (
            sum(r.total_probes for r in current.reports.values())
            // max(len(current.reports), 1)
        )

        if month == 1:
            prior_year, prior_month_num = year - 1, 12
        else:
            prior_year, prior_month_num = year, month - 1

        return {
            "prior_month": f"{prior_year}-{prior_month_num:02d}",
            "per_backend": per_backend,
            "best_improvement": improvements[0] if improvements else None,
            "worst_regression": regressions[0] if regressions else None,
            "new_probes_added": max(0, current_probe_count - prior_probe_count),
            "backends_added": sorted(active_backends - prior_backends),
            "backends_removed": sorted(prior_backends - active_backends),
        }

    # ── Artifact generation ───────────────────────────────────────────────────

    def _generate_artifacts(
        self,
        artifacts: BenchmarkArtifacts,
        comparison: ComparisonReport,
        delta: Optional[Dict],
    ) -> None:
        year, month = artifacts.year, artifacts.month

        probe_count = (
            sum(r.total_probes for r in comparison.reports.values())
            // max(len(comparison.reports), 1)
        )

        # Count owasp vs cm probes
        _first = next((r for r in comparison.reports.values() if r.total_probes > 0), None)
        owasp_probe_count = cm_probe_count = 0
        if _first:
            for _pr in _first.probe_results:
                if _pr.probe.id.startswith("CM-"):
                    cm_probe_count += 1
                else:
                    owasp_probe_count += 1

        # JSON
        json_payload: Dict[str, Any] = {
            "metadata": {
                "report_title": f"GuardrailProbe Benchmark — {calendar.month_name[month]} {year}",
                "generated_at": (artifacts.generated_at or datetime.now(timezone.utc)).isoformat(),
                "run_id": comparison.run_id,
                "probe_library_version": PROBE_LIBRARY_VERSION,
                "guardrailprobe_version": PROBE_LIBRARY_VERSION,
                "probe_count": probe_count,
                "owasp_probe_count": owasp_probe_count,
                "content_moderation_probe_count": cm_probe_count,
                "backends_tested": artifacts.backends_tested,
                "backends_skipped": artifacts.backends_skipped,
            },
            "results": _serialise_comparison(comparison),
            "delta": delta,
        }
        with open(artifacts.json_path, "w") as fh:
            json.dump(json_payload, fh, indent=2)
        logger.info("JSON  → %s", artifacts.json_path)

        # Markdown
        md = _render_markdown(artifacts, comparison, delta)
        with open(artifacts.markdown_path, "w") as fh:
            fh.write(md)
        logger.info("MD    → %s", artifacts.markdown_path)

        # PDF — signed with auto-generated (or user-supplied) PKCS#12 key
        try:
            from guardrailprobe.signer import ReportSigner  # noqa: PLC0415
            signer = ReportSigner()
            pdf_out = artifacts.json_path.replace(".json", ".pdf")
            signer.generate_signed_report(comparison, pdf_out)
            artifacts.pdf_path = pdf_out
            logger.info("PDF   → %s", pdf_out)
        except Exception as exc:
            if "mldsa" in str(exc) or "ImportError" in type(exc).__name__:
                logger.warning(
                    "PDF signing skipped — cryptography version conflict in site-packages. "
                    "Re-install with: pip install llamafirewall llm-guard "
                    "--target ./site-packages --ignore-installed --no-deps "
                    "(then manually install only missing transitive deps). "
                    "JSON and Markdown reports are unaffected."
                )
            else:
                logger.warning("PDF signing failed (non-critical): %s", exc)

    # ── docs/latest_index.json ────────────────────────────────────────────────

    def _update_docs_index(self, artifacts: BenchmarkArtifacts) -> None:
        if not self._docs_index.parent.exists():
            return

        index: Dict[str, Any]
        try:
            with open(self._docs_index) as fh:
                index = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            index = {"latest": None, "archive": []}

        cr = artifacts.comparison_report
        meta = {
            "year":           artifacts.year,
            "month":          artifacts.month,
            "month_name":     calendar.month_name[artifacts.month],
            "run_id":         artifacts.run_id,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "backends_tested": artifacts.backends_tested,
            "best_overall":   cr.best_overall if cr else None,
            "best_overall_pass_rate": (
                round(cr.reports[cr.best_overall].pass_rate * 100, 1)
                if (cr and cr.best_overall and cr.best_overall in cr.reports) else None
            ),
            "per_backend_rates": (
                {b: round(r.pass_rate * 100, 1) for b, r in cr.reports.items()}
                if cr else {}
            ),
            "probe_count":    artifacts.probe_count,
            "backends_skipped": artifacts.backends_skipped,
            "json_url":   f"benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.json",
            "markdown_url": f"benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.md",
            "pdf_url": (
                f"benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.pdf"
                if artifacts.pdf_path else None
            ),
        }

        index["latest"] = meta
        index["archive"] = [
            e for e in index.get("archive", [])
            if not (e.get("year") == artifacts.year and e.get("month") == artifacts.month)
        ]
        index["archive"].append(meta)
        index["archive"].sort(key=lambda e: (e["year"], e["month"]))

        with open(self._docs_index, "w") as fh:
            json.dump(index, fh, indent=2)
        logger.info("Index → %s", self._docs_index)


# ── Markdown renderer ─────────────────────────────────────────────────────────


def _render_markdown(
    artifacts: BenchmarkArtifacts,
    comparison: ComparisonReport,
    delta: Optional[Dict],
) -> str:
    year, month = artifacts.year, artifacts.month
    month_name = calendar.month_name[month]

    best = comparison.best_overall
    best_rate = comparison.reports[best].pass_rate if best in comparison.reports else 0.0

    improvement_backend = "none this month"
    improvement_delta   = "0.0"
    regression_backend  = "none this month"
    regression_delta    = "0.0"
    if delta:
        bi = delta.get("best_improvement")
        wr = delta.get("worst_regression")
        if bi:
            improvement_backend = bi["backend"]
            improvement_delta   = f"{bi['delta']:.1f}"
        if wr:
            regression_backend  = wr["backend"]
            regression_delta    = f"{abs(wr['delta']):.1f}"

    subs: Dict[str, str] = {
        "{MONTH}":                  month_name,
        "{MONTH_NUM}":              str(month),
        "{YEAR}":                   str(year),
        "{BEST_OVERALL_BACKEND}":   best,
        "{BEST_OVERALL_SCORE}":     f"{best_rate * 100:.1f}",
        "{RATIO_WINNER}":           _tm_ratio_winner(comparison),
        "{IMPROVEMENT_BACKEND}":    improvement_backend,
        "{IMPROVEMENT_DELTA}":      improvement_delta,
        "{REGRESSION_BACKEND}":     regression_backend,
        "{REGRESSION_DELTA}":       regression_delta,
        "{BACKENDS_TESTED_COUNT}":  str(len(comparison.backends_tested)),
        "{BACKENDS_SKIPPED_COUNT}": str(len(comparison.skipped_backends)),
        "{TOTAL_PROBES}":           str(sum(r.total_probes for r in comparison.reports.values())),
        "{GENERATED_AT}":           datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "{RUN_ID}":                 comparison.run_id,
        "{OVERALL_TABLE_ROWS}":     _tm_overall_rows(comparison, delta),
        "{CONTENT_MODERATION_TABLE_ROWS}": _tm_cm_rows(comparison),
        "{LATENCY_TABLE_ROWS}":     _tm_latency_rows(comparison),
        "{NOTABLE_BYPASSES_LIST}":  _tm_bypasses(comparison),
        "{SKIPPED_BACKENDS_TABLE}": _tm_skipped_table(comparison),
        "{DELTA_SECTION}":          _tm_delta_section(delta),
        "{VERSION}":                PROBE_LIBRARY_VERSION,
    }

    for ref, data in _tm_per_category(comparison).items():
        subs[f"{{{ref}_WINNER}}"]       = data["winner"]
        subs[f"{{{ref}_SCORE}}"]        = data["score"]
        subs[f"{{{ref}_SECOND}}"]       = data["second"]
        subs[f"{{{ref}_SECOND_SCORE}}"] = data["second_score"]

    result = BENCHMARK_TEMPLATE
    for key, value in subs.items():
        result = result.replace(key, value)
    return result


# ── Template section builders ─────────────────────────────────────────────────


def _tm_ratio_winner(comparison: ComparisonReport) -> str:
    best_ratio, winner = -1.0, "—"
    for bname, r in comparison.reports.items():
        if bname in comparison.skipped_backends or r.average_latency_ms <= 0:
            continue
        ratio = r.pass_rate * 1000 / max(r.average_latency_ms, 1)
        if ratio > best_ratio:
            best_ratio, winner = ratio, bname
    return winner


def _tm_overall_rows(comparison: ComparisonReport, delta: Optional[Dict]) -> str:
    rows: List[str] = []
    for backend in comparison.backends_tested:
        bname = backend.value
        if bname in comparison.skipped_backends:
            reason = comparison.skipped_backends[bname]
            rows.append(f"| {bname} | SKIPPED ({reason}) | — | — | — | — |")
            continue
        r = comparison.reports.get(bname)
        if not r:
            continue
        vs_last = "—"
        if delta:
            per_b = (delta.get("per_backend") or {}).get(bname, {})
            d = per_b.get("delta")
            if d is not None:
                sign = "+" if d >= 0 else ""
                flag = " 🔴" if d <= -5 else (" 🟢" if d >= 5 else "")
                vs_last = f"{sign}{d:.1f}%{flag}"
        cats = r.results_by_category
        best_cat  = max(cats, key=lambda c: cats[c].get("pass_rate", 0)) if cats else "—"
        worst_cat = min(cats, key=lambda c: cats[c].get("pass_rate", 1)) if cats else "—"
        rows.append(
            f"| {bname} | {r.pass_rate * 100:.1f}% | {vs_last} "
            f"| {best_cat} | {worst_cat} | {r.average_latency_ms:.0f} ms |"
        )
    return "\n".join(rows) or "| (no active backends) | — | — | — | — | — |"


def _tm_cm_rows(comparison: ComparisonReport) -> str:
    CM_RANGES = {"Hate": (1, 5), "Violence": (6, 10), "Sexual": (11, 15), "Self-Harm": (16, 20)}

    def _probe_num(pid: str) -> Optional[int]:
        if pid.startswith("CM-"):
            try:
                return int(pid[3:])
            except ValueError:
                pass
        return None

    rows: List[str] = []
    for backend in comparison.backends_tested:
        bname = backend.value
        if bname in comparison.skipped_backends:
            rows.append(f"| {bname} | — | — | — | — | SKIPPED |")
            continue
        r = comparison.reports.get(bname)
        if not r:
            continue
        cm = [pr for pr in r.probe_results if _probe_num(pr.probe.id) is not None]
        cats: Dict[str, str] = {}
        for cat_name, (lo, hi) in CM_RANGES.items():
            bucket = [pr for pr in cm if lo <= (_probe_num(pr.probe.id) or 0) <= hi]
            cats[cat_name] = (
                f"{sum(1 for pr in bucket if pr.passed is True) / len(bucket) * 100:.0f}%"
                if bucket else "—"
            )
        overall_str = (
            f"{sum(1 for pr in cm if pr.passed is True) / len(cm) * 100:.0f}%"
            if cm else "—"
        )
        rows.append(
            f"| {bname} | {cats['Hate']} | {cats['Violence']} "
            f"| {cats['Sexual']} | {cats['Self-Harm']} | {overall_str} |"
        )
    return "\n".join(rows) or "| (no data) | — | — | — | — | — |"


def _tm_latency_rows(comparison: ComparisonReport) -> str:
    active = sorted(
        (
            (bname, r)
            for bname, r in comparison.reports.items()
            if bname not in comparison.skipped_backends and r.total_probes > 0
        ),
        key=lambda x: x[1].average_latency_ms,
    )
    rows: List[str] = []
    for bname, r in active:
        ms = r.average_latency_ms
        if ms < 10:
            cat, rec = "Ultra-fast", "Real-time, high-throughput pipelines"
        elif ms < 200:
            cat, rec = "Fast", "Standard API protection"
        elif ms < 1000:
            cat, rec = "Moderate", "Batch processing, async pipelines"
        else:
            cat, rec = "Slow", "Offline analysis, compliance audits"
        rows.append(f"| {bname} | {r.pass_rate * 100:.1f}% | {ms:.0f} ms | {cat} | {rec} |")
    return "\n".join(rows) or "| (no active backends) | — | — | — | — |"


def _tm_bypasses(comparison: ComparisonReport) -> str:
    bypasses = _find_universal_bypasses(comparison)
    if not bypasses:
        return "No universal bypasses detected in this run."
    lines = ["| OWASP Category | Severity | Count |", "|:---------------|:--------:|:-----:|"]
    for entry in bypasses:
        lines.append(f"| {entry['owasp_ref']} | {entry['severity']} | {entry['count']} |")
    return "\n".join(lines)


def _tm_skipped_table(comparison: ComparisonReport) -> str:
    rows: List[str] = []
    for bname, reason in comparison.skipped_backends.items():
        if reason == REASON_CUSTOM_ENDPOINT:
            rows.append(
                f"| {bname} | {reason} | "
                "Generic HTTP adapter — set `GA_GUARD_API_URL` to benchmark a custom endpoint |"
            )
        else:
            rows.append(f"| {bname} | {reason} | Configure credentials |")
    return "\n".join(rows) or "| — | — | — |"


def _tm_delta_section(delta: Optional[Dict]) -> str:
    if delta is None:
        return "First benchmark — no prior month comparison available."
    lines: List[str] = []
    new_probes = delta.get("new_probes_added", 0)
    if new_probes:
        lines.append(f"**{new_probes} new probes** added since last month.\n")
    bi = delta.get("best_improvement")
    wr = delta.get("worst_regression")
    if bi:
        lines.append(f"**Best improvement:** {bi['backend']} +{bi['delta']:.1f}%\n")
    if wr:
        lines.append(f"**Worst regression:** {wr['backend']} {wr['delta']:.1f}%\n")
    per_b = delta.get("per_backend") or {}
    if per_b:
        lines += [
            "**All backend changes:**\n",
            "| Backend | Previous | Current | Change | Status |",
            "|---------|----------|---------|--------|--------|",
        ]
        for bname, data in per_b.items():
            prev   = f"{data['prior']:.1f}%" if data.get("prior") is not None else "—"
            curr   = f"{data['current']:.1f}%"
            chg    = f"{data['delta']:+.1f}%" if data.get("delta") is not None else "—"
            status = data.get("status", "—")
            lines.append(f"| {bname} | {prev} | {curr} | {chg} | {status} |")
    new_b = delta.get("backends_added") or []
    rem_b = delta.get("backends_removed") or []
    if new_b:
        lines.append(f"\n**New backends:** {', '.join(new_b)}")
    if rem_b:
        lines.append(f"**Removed backends:** {', '.join(rem_b)}")
    return "\n".join(lines) or "No significant changes from prior month."


def _tm_per_category(comparison: ComparisonReport) -> Dict[str, Dict[str, str]]:
    OWASP_REFS = [f"LLM{i:02d}" for i in range(1, 11)]
    active = {
        bname: r
        for bname, r in comparison.reports.items()
        if bname not in comparison.skipped_backends
    }
    result: Dict[str, Dict[str, str]] = {}
    for ref in OWASP_REFS:
        scores = sorted(
            (
                (bname, r.results_by_category.get(ref, {}).get("pass_rate", 0.0))
                for bname, r in active.items()
            ),
            key=lambda x: x[1],
            reverse=True,
        )
        result[ref] = {
            "winner":       scores[0][0]                 if scores           else "—",
            "score":        f"{scores[0][1] * 100:.0f}"  if scores           else "—",
            "second":       scores[1][0]                 if len(scores) > 1  else "—",
            "second_score": f"{scores[1][1] * 100:.0f}"  if len(scores) > 1  else "—",
        }
    return result


# ── Misc helpers ──────────────────────────────────────────────────────────────


def _find_universal_bypasses(comparison: ComparisonReport) -> List[Dict]:
    if not comparison.reports:
        return []
    active_backends = [
        bname for bname in comparison.reports
        if bname not in comparison.skipped_backends
    ]
    if not active_backends:
        return []

    failed_on: Dict[str, set] = defaultdict(set)
    probe_meta: Dict[str, Dict] = {}

    for bname in active_backends:
        for pr in comparison.reports[bname].probe_results:
            if pr.passed is False:
                failed_on[pr.probe.id].add(bname)
                probe_meta[pr.probe.id] = {
                    "owasp_ref": pr.probe.owasp_ref,
                    "severity":  pr.probe.severity,
                }

    n_backends = len(active_backends)
    groups: Dict[tuple, int] = {}
    for pid, backends in failed_on.items():
        if len(backends) == n_backends:
            m = probe_meta[pid]
            key = (m["owasp_ref"], m["severity"])
            groups[key] = groups.get(key, 0) + 1

    return [
        {"owasp_ref": k[0], "severity": k[1], "count": v}
        for k, v in sorted(groups.items())
    ]


def _prior_month_filename(year: int, month: int) -> str:
    if month == 1:
        return f"benchmark_{year - 1:04d}_12.json"
    return f"benchmark_{year:04d}_{month - 1:02d}.json"
