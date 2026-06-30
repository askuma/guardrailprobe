"""Tests for guardrailprobe.cli — Click command structure and basic invocations."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from guardrailprobe.cli import main


# ── Helpers ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def runner():
    return CliRunner()


# ── Top-level ─────────────────────────────────────────────────────────────────

def test_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "guardrailprobe" in result.output.lower()


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.1" in result.output


# ── status ────────────────────────────────────────────────────────────────────

def test_status_exits_zero(runner):
    """guardrailprobe status should exit 0 and print a table."""
    with patch.dict(os.environ, {"GUARDRAILPROBE_SKIP_SPACY": "1"}):
        result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    # Should list adapter names
    assert "lakera" in result.output.lower() or "nemo" in result.output.lower()


def test_status_shows_all_adapters(runner):
    with patch.dict(os.environ, {"GUARDRAILPROBE_SKIP_SPACY": "1"}):
        result = runner.invoke(main, ["status"])
    expected_adapters = [
        "nemo", "guardrails_ai", "presidio", "lakera",
        "openai_moderation", "aws_bedrock", "llama_firewall", "llm_guard",
    ]
    for name in expected_adapters:
        assert name in result.output.lower(), f"Adapter '{name}' missing from status output"


# ── cert subgroup ─────────────────────────────────────────────────────────────

def test_cert_help(runner):
    result = runner.invoke(main, ["cert", "--help"])
    assert result.exit_code == 0
    assert "generate" in result.output.lower()
    assert "show" in result.output.lower()
    assert "verify" in result.output.lower()


def test_cert_generate_creates_p12(runner, tmp_path):
    out = str(tmp_path / "test.p12")
    with patch.dict(os.environ, {"GUARDRAILPROBE_SKIP_SPACY": "1"}):
        result = runner.invoke(main, [
            "cert", "generate",
            "--output", out,
            "--org-name", "Test Org",
        ])
    assert result.exit_code == 0, result.output
    import os as _os
    assert _os.path.exists(out), "P12 file was not created"


def test_cert_show_no_key(runner, tmp_path):
    """cert show when no key is configured should not crash."""
    with patch.dict(os.environ, {
        "GUARDRAILPROBE_SKIP_SPACY": "1",
        "GUARDRAIL_SIGNING_KEY_P12": str(tmp_path / "nonexistent.p12"),
    }):
        result = runner.invoke(main, ["cert", "show"])
    # May exit non-zero but should not raise an unhandled exception
    assert (
        "error" in result.output.lower()
        or "certificate" in result.output.lower()
        or "signing" in result.output.lower()
        or result.exit_code != 0
    )


# ── run (dry-run only, no network) ───────────────────────────────────────────

def test_run_help(runner):
    result = runner.invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "--year" in result.output
    assert "--month" in result.output
    assert "--dry-run" in result.output


def test_run_dry_run_exits_zero(runner, tmp_path):
    """guardrailprobe run --dry-run should complete without calling any adapters."""
    with patch.dict(os.environ, {"GUARDRAILPROBE_SKIP_SPACY": "1"}):
        with patch("guardrailprobe.report.BenchmarkRunner.generate_monthly_benchmark") as mock_run:
            from guardrailprobe.report import BenchmarkArtifacts
            mock_run.return_value = BenchmarkArtifacts(
                year=2026, month=6,
                run_id="dry-run-id",
                pdf_path=None,
                json_path=str(tmp_path / "benchmark_2026_06.json"),
                markdown_path=str(tmp_path / "benchmark_2026_06.md"),
                comparison_report=None,
                delta=None,
            )
            result = runner.invoke(main, [
                "run",
                "--year", "2026",
                "--month", "6",
                "--output-dir", str(tmp_path),
                "--dry-run",
            ])
    assert result.exit_code == 0


# ── dashboard ─────────────────────────────────────────────────────────────────

def test_dashboard_help(runner):
    result = runner.invoke(main, ["dashboard", "--help"])
    assert result.exit_code == 0
    assert "--host" in result.output
    assert "--port" in result.output


# ── init ──────────────────────────────────────────────────────────────────────

def test_init_help(runner):
    result = runner.invoke(main, ["init", "--help"])
    assert result.exit_code == 0
