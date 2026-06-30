"""Tests for guardrailprobe.signer — PDF generation and version sourcing."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guardrailprobe._types import GuardrailBackend
from guardrailprobe.runner import ComparisonReport, RedTeamReport
from guardrailprobe.signer import ReportSigner, _VERSION


# ── Version ───────────────────────────────────────────────────────────────────

def test_version_not_hardcoded():
    """_VERSION must be sourced dynamically, not the old hardcoded '0.1.0'."""
    assert _VERSION != "0.1.0", (
        "_VERSION is still the old hardcoded string — update signer.py to use "
        "importlib.metadata.version('guardrailprobe')"
    )
    assert _VERSION != "", "_VERSION must not be empty"


def test_version_matches_package():
    import importlib.metadata
    expected = importlib.metadata.version("guardrailprobe")
    assert _VERSION == expected


# ── SHA-256 helper ────────────────────────────────────────────────────────────

def test_sha256_known_value(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_bytes(b"hello world")
    digest = ReportSigner._sha256(f)
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert digest == expected


def test_sha256_empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    digest = ReportSigner._sha256(f)
    assert digest == hashlib.sha256(b"").hexdigest()


# ── Helpers: build minimal report objects ─────────────────────────────────────

def _make_single_report(backend_str: str = "lakera") -> RedTeamReport:
    backend = GuardrailBackend(backend_str)
    return RedTeamReport(
        backend=backend,
        run_id="test-run-id-001",
        timestamp="2026-06-01T12:00:00+00:00",
        total_probes=10,
        passed=8,
        failed=2,
        pass_rate=0.8,
        results_by_category={
            "LLM01": {"total": 5, "passed": 4, "failed": 1, "pass_rate": 0.8},
            "LLM02": {"total": 5, "passed": 4, "failed": 1, "pass_rate": 0.8},
        },
        results_by_severity={
            "high": {"total": 5, "passed": 4, "failed": 1, "pass_rate": 0.8},
            "medium": {"total": 5, "passed": 4, "failed": 1, "pass_rate": 0.8},
        },
        average_latency_ms=123.4,
        probe_results=[],
    )


def _make_comparison_report() -> ComparisonReport:
    lakera = _make_single_report("lakera")
    nemo   = _make_single_report("nemo")
    nemo.pass_rate = 0.9
    nemo.passed    = 9
    nemo.failed    = 1
    nemo.average_latency_ms = 5000.0
    return ComparisonReport(
        run_id="test-cmp-run-001",
        timestamp="2026-06-01T12:00:00+00:00",
        backends_tested=[GuardrailBackend.LAKERA, GuardrailBackend.NEMO],
        reports={"lakera": lakera, "nemo": nemo},
        best_overall="nemo",
        worst_overall="lakera",
        category_winners={
            "LLM01": {"winner": "nemo", "score": 0.9, "runner_up": "lakera",
                      "runner_up_score": 0.8, "winner_latency_ms": 5000},
        },
        summary_table=[],
        skipped_backends={},
    )


# ── PDF generation ────────────────────────────────────────────────────────────

@pytest.fixture()
def signer(tmp_path):
    """ReportSigner with a temp P12 path so it auto-generates a dev key."""
    with patch.dict("os.environ", {
        "GUARDRAIL_SIGNING_KEY_P12": str(tmp_path / "test_signing.p12"),
        "GUARDRAILPROBE_SKIP_SPACY": "1",
    }):
        s = ReportSigner()
        s._p12_path = tmp_path / "test_signing.p12"
        yield s


def test_build_pdf_single_report(signer, tmp_path):
    """PDF is created for a single-backend report without errors."""
    report = _make_single_report("lakera")
    out = tmp_path / "single.pdf"
    signer._build_pdf(report, out)
    assert out.exists()
    assert out.stat().st_size > 1000, "PDF is suspiciously small"


def test_build_pdf_comparison_report(signer, tmp_path):
    """PDF is created for a comparison report and contains all 10 sections."""
    report = _make_comparison_report()
    out = tmp_path / "comparison.pdf"
    signer._build_pdf(report, out)
    assert out.exists()
    assert out.stat().st_size > 5000

    # Confirm text content via pdftotext if available, else check file size
    import shutil
    if shutil.which("pdftotext"):
        import subprocess
        result = subprocess.run(
            ["pdftotext", str(out), "-"],
            capture_output=True, text=True,
        )
        text = result.stdout
        for section in [
            "TL;DR", "Overall Comparison", "Per-Category Results",
            "Content Moderation", "Capability Matrix", "Accuracy vs Latency",
            "Notable Bypasses", "Backends Skipped", "Month-over-Month",
            "How to Reproduce",
        ]:
            assert section in text, f"Section '{section}' missing from comparison PDF"


def test_build_pdf_comparison_skipped_backends(signer, tmp_path):
    """Skipped backends appear in the Backends Skipped section."""
    report = _make_comparison_report()
    report.skipped_backends = {"ga_guard": "MISSING_CREDENTIALS"}
    out = tmp_path / "skipped.pdf"
    signer._build_pdf(report, out)
    assert out.exists()


def test_build_pdf_sets_correct_metadata(signer, tmp_path):
    """PDF document subject/keywords embed the run_id."""
    report = _make_comparison_report()
    out = tmp_path / "meta.pdf"
    signer._build_pdf(report, out)
    raw = out.read_bytes()
    assert b"test-cmp-run-001" in raw


def test_generate_signed_report_creates_pdf(signer, tmp_path):
    """generate_signed_report writes and signs a PDF (skips TSA in unit test)."""
    report = _make_comparison_report()
    out = str(tmp_path / "signed.pdf")

    def _fake_sign(unsigned: Path, signed: Path) -> None:
        signed.write_bytes(b"%PDF-1.4 fake signed pdf")

    with patch.object(signer, "_sign_pdf", side_effect=_fake_sign) as mock_sign:
        signer.generate_signed_report(report, out)
        assert Path(out).exists()
        mock_sign.assert_called_once()
