"""
GuardrailProbe CLI — entry point for the ``guardrailprobe`` command.

Commands
--------
guardrailprobe run       — run the full benchmark suite
guardrailprobe init      — interactive first-run setup wizard
guardrailprobe cert      — manage PDF signing certificates
guardrailprobe dashboard — launch the probe-builder web UI
guardrailprobe status    — show credential status for all adapters
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import click
from dotenv import load_dotenv

load_dotenv()


# ── Main group ────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(package_name="guardrailprobe")
def main() -> None:
    """GuardrailProbe — Independent AI Guardrail Benchmark Tool."""


# ── run ───────────────────────────────────────────────────────────────────────


@main.command()
@click.option("--year",  type=int,  default=None, help="Report year (default: current year).")
@click.option("--month", type=int,  default=None, help="Report month 1-12 (default: current month).")
@click.option("--backends", type=str, default="", help="Comma-separated backend names to test.")
@click.option("--output-dir", type=click.Path(), default="./docs/benchmarks",
              help="Output directory for artifacts.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Skip unreachable backends silently.")
@click.option("--no-pdf", is_flag=True, default=False,
              help="Skip PDF generation.")
@click.option("--json-only", is_flag=True, default=False,
              help="Write JSON artifact only.")
def run(year, month, backends, output_dir, dry_run, no_pdf, json_only) -> None:
    """Run the full benchmark suite and generate reports."""
    from guardrailprobe._types import GuardrailBackend
    from guardrailprobe.report import BenchmarkRunner

    now = datetime.now(timezone.utc)
    year  = year  or now.year
    month = month or now.month

    if not 1 <= month <= 12:
        click.echo(f"Error: --month must be 1-12, got {month}", err=True)
        sys.exit(1)

    backend_list = None
    if backends:
        try:
            backend_list = [GuardrailBackend(b.strip()) for b in backends.split(",") if b.strip()]
        except ValueError as exc:
            click.echo(f"Error: invalid backend — {exc}", err=True)
            click.echo(
                "Valid backends: " + ", ".join(b.value for b in GuardrailBackend), err=True
            )
            sys.exit(1)

    if no_pdf:
        os.environ["GUARDRAILPROBE_SKIP_PDF"] = "1"

    runner = BenchmarkRunner()

    click.echo(f"Running benchmark for {year}-{month:02d}…")
    if backend_list:
        click.echo(f"Backends: {', '.join(b.value for b in backend_list)}")
    else:
        click.echo("Backends: all configured")

    from rich.progress import (  # noqa: PLC0415
        BarColumn, MofNCompleteColumn, Progress,
        SpinnerColumn, TextColumn, TimeRemainingColumn,
    )

    _lock = threading.Lock()
    _backend_progress: dict = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("probes"),
        TimeRemainingColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Benchmarking…", total=None)

        def progress_cb(backend_val: str, done: int, total: int) -> None:
            with _lock:
                _backend_progress[backend_val] = (done, total)
                total_done = sum(v[0] for v in _backend_progress.values())
                total_all  = sum(v[1] for v in _backend_progress.values())
            progress.update(task, completed=total_done, total=total_all or None,
                            description=f"[bold]{backend_val}")

        try:
            arts = runner.generate_monthly_benchmark(
                year=year,
                month=month,
                backends=backend_list,
                dry_run=dry_run,
                output_dir=Path(output_dir),
                progress_cb=progress_cb,
            )
        except Exception as exc:
            click.echo(f"\nBenchmark FAILED: {exc}", err=True)
            if os.getenv("DEBUG"):
                import traceback  # noqa: PLC0415
                traceback.print_exc()
            sys.exit(1)

    import calendar
    click.echo(f"\nBenchmark complete — {calendar.month_name[month]} {year}")
    click.echo(f"  JSON:     {arts.json_path}")
    click.echo(f"  Markdown: {arts.markdown_path}")
    if arts.pdf_path:
        click.echo(f"  PDF:      {arts.pdf_path}")
    else:
        click.echo("  PDF:      (skipped)")

    if arts.comparison_report:
        cr = arts.comparison_report
        click.echo(f"\n  Best overall: {cr.best_overall}")
        for b in cr.backends_tested:
            r = cr.reports.get(b.value)
            if r and r.total_probes:
                click.echo(
                    f"  {b.value:<22}  {r.pass_rate * 100:.1f}%  ({r.passed}/{r.total_probes})"
                )


# ── status ────────────────────────────────────────────────────────────────────


@main.command()
def status() -> None:
    """Show credential and readiness status for all 11 adapters."""
    from guardrailprobe.adapters import REGISTRY
    from rich.console import Console
    from rich.table import Table

    console = Console()
    tbl = Table(title="GuardrailProbe Adapter Status", show_lines=True)
    tbl.add_column("Backend",  style="bold")
    tbl.add_column("Status",   justify="center")
    tbl.add_column("Ready",    justify="center")
    tbl.add_column("Note")

    for info in REGISTRY.status_report():
        ready   = "[green]YES[/green]" if info["ready"] else "[red]NO[/red]"
        status  = info["status"]
        colour  = "green" if info["ready"] else "yellow" if "no_llm" in status else "red"
        tbl.add_row(
            info["backend"],
            f"[{colour}]{status}[/{colour}]",
            ready,
            info.get("message", ""),
        )

    console.print(tbl)


# ── init ──────────────────────────────────────────────────────────────────────


@main.command()
@click.option("--env-file", default=".env", help="Path to write credentials to.")
def init(env_file: str) -> None:
    """Interactive first-run setup wizard.

    Walks through each adapter and collects API keys / endpoints,
    writing them to a .env file you can load on subsequent runs.
    """
    click.echo("\nGuardrailProbe first-run setup wizard\n" + "=" * 40)
    click.echo(
        "This wizard helps you configure API credentials for each adapter.\n"
        "Press ENTER to skip any adapter you don't have credentials for.\n"
    )

    ENV_VARS = [
        ("Lakera Guard",             "LAKERA_GUARD_API_KEY",         "API key from app.lakera.ai"),
        ("OpenAI Moderation",        "OPENAI_API_KEY",               "OpenAI API key"),
        ("Azure Content Safety",     "AZURE_CONTENT_SAFETY_ENDPOINT","Azure endpoint URL"),
        ("Azure Content Safety",     "AZURE_CONTENT_SAFETY_KEY",     "Azure subscription key"),
        ("Azure Prompt Shields",     "AZURE_CONTENT_SAFETY_ENDPOINT","Same Azure endpoint as above"),
        ("AWS Bedrock Guardrail ID", "AWS_BEDROCK_GUARDRAIL_ID",     "Guardrail ID from AWS console"),
        ("AWS Bedrock Region",       "AWS_DEFAULT_REGION",           "e.g. us-east-1"),
        ("Custom HTTP endpoint",     "GA_GUARD_API_URL",             "https://your-guardrail-api/check"),
        ("NeMo — LLM backend key",   "OPENAI_API_KEY",               "Already set above if using OpenAI"),
    ]

    collected: dict = {}
    for label, var, hint in ENV_VARS:
        if var in collected:
            continue
        val = click.prompt(
            f"  {label}\n  {var} ({hint})",
            default="",
            show_default=False,
        ).strip()
        if val:
            collected[var] = val

    if not collected:
        click.echo("\nNo credentials entered — nothing written.")
        return

    env_path = Path(env_file)
    existing = env_path.read_text() if env_path.exists() else ""
    with open(env_path, "a") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write("# Added by guardrailprobe init\n")
        for k, v in collected.items():
            fh.write(f"{k}={v}\n")

    click.echo(f"\nCredentials written to {env_path}")
    click.echo("Run 'guardrailprobe status' to verify all adapters are ready.")


# ── cert ──────────────────────────────────────────────────────────────────────


@main.group()
def cert() -> None:
    """Manage PDF signing certificates."""


@cert.command("show")
def cert_show() -> None:
    """Show current signing certificate details."""
    p12_path = Path(os.getenv("GUARDRAIL_SIGNING_KEY_P12", "guardrail_signing.p12"))
    if not p12_path.exists():
        click.echo(
            "No signing certificate found.  Run 'guardrailprobe cert generate' to create one.",
            err=True,
        )
        return

    try:
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        passphrase = os.getenv("GUARDRAIL_SIGNING_KEY_PASS", "").encode() or None
        data = p12_path.read_bytes()
        p12 = load_pkcs12(data, passphrase)
        cert = p12.cert.certificate
        click.echo(f"Certificate: {p12_path}")
        click.echo(f"Subject:     {cert.subject.rfc4514_string()}")
        click.echo(f"Issuer:      {cert.issuer.rfc4514_string()}")
        click.echo(f"Valid from:  {cert.not_valid_before_utc}")
        click.echo(f"Valid until: {cert.not_valid_after_utc}")
        click.echo(f"Serial:      {cert.serial_number}")
    except Exception as exc:
        click.echo(f"Error reading certificate: {exc}", err=True)


@cert.command("generate")
@click.option("--output", default="guardrail_signing.p12", help="Output path for PKCS#12 file.")
@click.option("--passphrase", default="", help="Passphrase to protect the key (default: none).")
@click.option("--org-name", default="GuardrailProbe", help="Organisation name in the certificate.")
def cert_generate(output: str, passphrase: str, org_name: str) -> None:
    """Generate a self-signed development signing certificate."""
    from guardrailprobe.signer import _generate_self_signed_p12

    p12_path = Path(output)
    if p12_path.exists():
        if not click.confirm(f"{p12_path} already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    _generate_self_signed_p12(p12_path, passphrase.encode())
    click.echo(f"Generated signing certificate: {p12_path}")
    click.echo("Set GUARDRAIL_SIGNING_KEY_P12=" + str(p12_path) + " in your .env")


@cert.command("verify")
@click.argument("pdf_path", type=click.Path(exists=True))
def cert_verify(pdf_path: str) -> None:
    """Verify the digital signature of a signed report PDF."""
    from guardrailprobe.signer import ReportSigner

    try:
        signer = ReportSigner()
        result = signer.verify_report(pdf_path)
    except ImportError as exc:
        click.echo(f"Missing dependency: {exc}", err=True)
        sys.exit(1)

    if result["valid"]:
        click.echo(f"VALID  — signed at {result.get('signed_at', 'unknown')}")
        if result.get("run_id"):
            click.echo(f"Run ID: {result['run_id']}")
    else:
        detail = result.get("detail", "unknown error")
        click.echo(f"INVALID — {detail}", err=True)
        sys.exit(1)


# ── dashboard ─────────────────────────────────────────────────────────────────


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to.")
@click.option("--port", default=8080, help="Port to listen on.")
@click.option("--debug", is_flag=True, default=False, help="Enable Flask debug mode.")
def dashboard(host: str, port: int, debug: bool) -> None:
    """Launch the probe-builder web UI."""
    from guardrailprobe.dashboard import create_app

    app = create_app()
    click.echo(f"GuardrailProbe dashboard running at http://{host}:{port}")
    click.echo("Press CTRL+C to stop.")
    app.run(host=host, port=port, debug=debug)
