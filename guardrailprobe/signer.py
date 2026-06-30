"""
PDF generation, digital signing, and verification for GuardrailProbe reports.

Signing flow
------------
1. Build PDF from RedTeamReport / ComparisonReport (reportlab)
2. Append an empty signature field (pyhanko)
3. Sign with platform private key (pyhanko SimpleSigner)
4. Embed RFC 3161 trusted timestamp (HTTPTimeStamper)

Verification flow
-----------------
1. Read embedded signatures from PDF (pyhanko PdfFileReader)
2. Validate cryptographic integrity (pyhanko_certvalidator)
3. Return {valid, signed_at, run_id}

Key management
--------------
GUARDRAIL_SIGNING_KEY_P12  path to PKCS#12 signing key
                           (auto-generated as guardrail_signing.p12 if absent)
GUARDRAIL_SIGNING_KEY_PASS passphrase for the PKCS#12 file (default: empty)
GUARDRAIL_TSA_URL          RFC 3161 timestamp authority
                           dev default : http://freetsa.org/tsr
                           DigiCert    : http://timestamp.digicert.com
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("ReportSigner")

_PYHANKO_AVAILABLE  = importlib.util.find_spec("pyhanko")   is not None
_REPORTLAB_AVAILABLE = importlib.util.find_spec("reportlab") is not None

try:
    _VERSION = importlib.metadata.version("guardrailprobe")
except importlib.metadata.PackageNotFoundError:
    _VERSION = "unknown"


# ── Self-signed certificate generation ───────────────────────────────────────


def _generate_self_signed_p12(p12_path: Path, passphrase: bytes = b"") -> None:
    """Generate a self-signed RSA-2048 certificate and save as PKCS#12."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "GuardrailProbe Report Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GuardrailProbe"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    enc = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    p12_bytes = serialize_key_and_certificates(
        name=b"guardrailprobe-report-signer",
        key=key, cert=cert, cas=None,
        encryption_algorithm=enc,
    )
    p12_path.write_bytes(p12_bytes)
    logger.warning(
        "Auto-generated self-signed dev signing key at %s"
        " — NOT suitable for production. Set GUARDRAIL_SIGNING_KEY_P12 to a"
        " production-issued PKCS#12 certificate.",
        p12_path,
    )


# ── OWASP label map ───────────────────────────────────────────────────────────

_OWASP_LABELS: Dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model DoS",
    "LLM05": "Supply Chain",
    "LLM06": "Sensitive Info Disclosure",
    "LLM07": "Insecure Plugin",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}


# ── Signing configuration ─────────────────────────────────────────────────────


@dataclass
class SigningConfig:
    source: str = "auto"
    cert_path: str = ""
    cert_pass: str = ""
    org_name: str = ""
    tsa_url: str = "http://freetsa.org/tsr"

    @classmethod
    def from_env(cls) -> "SigningConfig":
        return cls(
            source="file" if os.getenv("GUARDRAIL_SIGNING_KEY_P12") else "auto",
            cert_path=os.getenv("GUARDRAIL_SIGNING_KEY_P12", ""),
            cert_pass=os.getenv("GUARDRAIL_SIGNING_KEY_PASS", ""),
            org_name=os.getenv("GUARDRAIL_SIGNING_ORG", "GuardrailProbe Benchmark"),
            tsa_url=os.getenv("GUARDRAIL_TSA_URL", "http://freetsa.org/tsr"),
        )


# ── Main class ────────────────────────────────────────────────────────────────


class ReportSigner:
    """Generates signed PDFs for red-team reports and verifies their integrity.

    Instantiate once per process.  The PKCS#12 signing key is loaded (or
    auto-generated) lazily on the first call to generate_signed_report.
    """

    def __init__(self) -> None:
        if not _PYHANKO_AVAILABLE:
            raise ImportError(
                "pyhanko is required for PDF signing. "
                "Install it with: pip install 'guardrailprobe[pdf]'"
            )
        if not _REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required for PDF generation. "
                "Install it with: pip install 'guardrailprobe[pdf]'"
            )
        self._signer = None
        raw_pass = os.getenv("GUARDRAIL_SIGNING_KEY_PASS", "")
        self._passphrase = raw_pass.encode() if raw_pass else b""
        self._tsa_url = os.getenv("GUARDRAIL_TSA_URL", "http://timestamp.digicert.com")

        # Use the configured P12 only if it already exists (it may live on a
        # read-only mount).  Otherwise fall back to a writable auto-generated key
        # in the reports directory so signing never silently fails.
        configured = Path(os.getenv("GUARDRAIL_SIGNING_KEY_P12", ""))
        if configured.name and configured.exists():
            self._p12_path = configured
        else:
            self._p12_path = (
                Path("/app/reports/guardrail_signing.p12")
                if Path("/app").is_dir()
                else Path("reports/guardrail_signing.p12")
            )

    def _get_signer(self):
        if self._signer is not None:
            return self._signer
        if not self._p12_path.exists():
            self._p12_path.parent.mkdir(parents=True, exist_ok=True)
            _generate_self_signed_p12(self._p12_path, self._passphrase)
        from pyhanko.sign import signers as _signers  # noqa: PLC0415
        self._signer = _signers.SimpleSigner.load_pkcs12(
            pfx_file=str(self._p12_path),
            passphrase=self._passphrase or None,
        )
        return self._signer

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── PDF generation (reportlab) ────────────────────────────────────────────

    def _build_pdf(self, report: Any, path: Path) -> None:
        from reportlab.lib import colors  # noqa: PLC0415
        from reportlab.lib.pagesizes import A4  # noqa: PLC0415
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # noqa: PLC0415
        from reportlab.lib.units import mm  # noqa: PLC0415
        from reportlab.platypus import (  # noqa: PLC0415
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )

        is_comparison = hasattr(report, "backends_tested")
        run_id = report.run_id

        ts = report.timestamp
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(timezone.utc)
        month_year = ts.strftime("%B %Y") if hasattr(ts, "strftime") else datetime.now(timezone.utc).strftime("%B %Y")

        if is_comparison:
            pdf_title = f"GuardrailProbe Independent Benchmark — {month_year}"
        else:
            _bval = report.backend.value if hasattr(report.backend, "value") else str(report.backend)
            pdf_title = f"GuardrailProbe Security Report — {_bval.replace('_', ' ').title()}"

        styles = getSampleStyleSheet()
        H1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18, spaceAfter=6)
        H2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceAfter=4)
        BL = ParagraphStyle("bl", parent=styles["Normal"], fontSize=8, leftIndent=4 * mm)

        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            title=pdf_title,
            subject=f"run_id={run_id}",
            keywords=f"run_id={run_id}",
            author="GuardrailProbe v" + _VERSION,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
        )

        _BG  = colors.Color(0.15, 0.15, 0.15)
        _WT  = colors.white
        _R1  = colors.Color(0.95, 0.95, 0.95)
        _GRD = colors.Color(0.7, 0.7, 0.7)

        def _pass_color(rate: float):
            if rate >= 0.8:
                return colors.Color(0.0, 0.5, 0.0)
            if rate >= 0.5:
                return colors.Color(0.6, 0.4, 0.0)
            return colors.Color(0.7, 0.0, 0.0)

        def _base_style(n_cols: int) -> list:
            return [
                ("BACKGROUND",   (0, 0), (n_cols - 1, 0), _BG),
                ("TEXTCOLOR",    (0, 0), (n_cols - 1, 0), _WT),
                ("FONTNAME",     (0, 0), (n_cols - 1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_R1, _WT]),
                ("GRID",         (0, 0), (-1, -1), 0.4, _GRD),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",   (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
                ("LEFTPADDING",  (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]

        story: list = []

        # Title
        story.append(Paragraph(pdf_title, H1))
        story.append(Spacer(1, 3 * mm))

        def _backend_str(b: Any) -> str:
            return b.value if hasattr(b, "value") else str(b)

        # Metadata block
        meta_rows: list = [
            ["Run ID", run_id],
            ["Timestamp", str(report.timestamp)],
            ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")],
        ]
        if is_comparison:
            meta_rows += [
                ["Backends tested", ", ".join(_backend_str(b) for b in report.backends_tested)],
                ["Best overall", str(report.best_overall)],
                ["Worst overall", str(report.worst_overall)],
            ]
        else:
            meta_rows += [
                ["Backend", _backend_str(report.backend)],
                ["Total probes", str(report.total_probes)],
                ["Pass rate", f"{report.pass_rate * 100:.1f}%"],
                ["Average latency", f"{report.average_latency_ms:.1f} ms"],
            ]

        meta_tbl = Table(meta_rows, colWidths=[45 * mm, 120 * mm])
        meta_tbl.setStyle(TableStyle(_base_style(2)))
        story.append(meta_tbl)
        story.append(Spacer(1, 5 * mm))

        # Per-category breakdown
        if not is_comparison:
            story.append(Paragraph("Results by OWASP Category", H2))
            cat_rows = [["Ref", "Category", "Total", "Passed", "Failed", "Pass %"]]
            for ref in sorted(report.results_by_category.keys()):
                d = report.results_by_category[ref]
                rate = d.get("pass_rate", 0)
                cat_rows.append([
                    ref,
                    _OWASP_LABELS.get(ref, ref),
                    str(d.get("total", 0)),
                    str(d.get("passed", 0)),
                    str(d.get("failed", 0)),
                    f"{rate * 100:.0f}%",
                ])

            col_w = [14 * mm, 52 * mm, 17 * mm, 17 * mm, 17 * mm, 17 * mm]
            cat_tbl = Table(cat_rows, colWidths=col_w)
            cat_style = _base_style(6)
            for i, row in enumerate(cat_rows[1:], 1):
                try:
                    rate_val = float(row[5].rstrip("%")) / 100
                except ValueError:
                    rate_val = 0.0
                cat_style += [
                    ("TEXTCOLOR", (5, i), (5, i), _pass_color(rate_val)),
                    ("FONTNAME",  (5, i), (5, i), "Helvetica-Bold"),
                ]
            cat_tbl.setStyle(TableStyle(cat_style))
            story.append(cat_tbl)
            story.append(Spacer(1, 4 * mm))

            story.append(Paragraph("Results by Severity", H2))
            sev_rows = [["Severity", "Total", "Passed", "Failed", "Pass %"]]
            for sev in ("critical", "high", "medium", "low"):
                d = report.results_by_severity.get(sev)
                if d and d.get("total", 0):
                    rate = d.get("pass_rate", 0)
                    sev_rows.append([
                        sev.upper(),
                        str(d.get("total", 0)),
                        str(d.get("passed", 0)),
                        str(d.get("failed", 0)),
                        f"{rate * 100:.0f}%",
                    ])
            sev_tbl = Table(sev_rows, colWidths=[28 * mm] * 5)
            sev_tbl.setStyle(TableStyle(_base_style(5)))
            story.append(sev_tbl)

        else:
            # ── TL;DR ─────────────────────────────────────────────────────────
            story.append(Paragraph("TL;DR", H2))
            _best_ratio_name = "—"
            _best_ratio_val = -1.0
            for _bname, _r in report.reports.items():
                if _bname in report.skipped_backends:
                    continue
                _lat = _r.average_latency_ms or 0.001
                _ratio = _r.pass_rate / _lat
                if _ratio > _best_ratio_val:
                    _best_ratio_val = _ratio
                    _best_ratio_name = _bname
            _n_tested = len(report.backends_tested)
            _n_skipped = len(report.skipped_backends)
            _total_probes = sum(_r.total_probes for _r in report.reports.values())
            _ts_str = ts.strftime("%Y-%m-%d %H:%M UTC") if hasattr(ts, "strftime") else str(report.timestamp)
            tldr_rows = [
                ["Winner",                          str(report.best_overall)],
                ["Best accuracy/latency ratio",     _best_ratio_name],
                ["Biggest improvement vs last month", "—"],
                ["Biggest regression vs last month",  "—"],
                ["Backends tested",                 str(_n_tested)],
                ["Backends skipped",                str(_n_skipped)],
                ["Total probes run",                str(_total_probes)],
                ["Report generated",                _ts_str],
                ["Run ID",                          run_id],
            ]
            tldr_tbl = Table(tldr_rows, colWidths=[70 * mm, 95 * mm])
            tldr_tbl.setStyle(TableStyle(_base_style(2)))
            story.append(tldr_tbl)
            story.append(Spacer(1, 5 * mm))

            # ── Overall Comparison ────────────────────────────────────────────
            story.append(Paragraph("Overall Comparison", H2))
            ov_rows = [["Backend", "Overall %", "vs Last Month", "Best Category", "Worst Category", "Avg Latency"]]
            for _b in report.backends_tested:
                _bval = _backend_str(_b)
                if _bval in report.skipped_backends:
                    ov_rows.append([_bval, f"SKIPPED ({report.skipped_backends[_bval]})", "—", "—", "—", "—"])
                    continue
                _r = report.reports.get(_bval)
                if not _r:
                    continue
                _cat_scores = {
                    _ref: _d.get("pass_rate", 0.0)
                    for _ref, _d in _r.results_by_category.items()
                    if _ref.startswith("LLM")
                }
                _best_cat = max(_cat_scores, key=lambda _k: _cat_scores[_k]) if _cat_scores else "—"
                _worst_cat = min(_cat_scores, key=lambda _k: _cat_scores[_k]) if _cat_scores else "—"
                ov_rows.append([
                    _bval,
                    f"{_r.pass_rate * 100:.1f}%",
                    "—",
                    _best_cat,
                    _worst_cat,
                    f"{_r.average_latency_ms:.0f} ms",
                ])
            ov_tbl = Table(ov_rows, colWidths=[35 * mm, 20 * mm, 22 * mm, 22 * mm, 24 * mm, 22 * mm])
            ov_style = _base_style(6)
            for _i, _row in enumerate(ov_rows[1:], 1):
                if "%" in _row[1] and "SKIPPED" not in _row[1]:
                    try:
                        _rate = float(_row[1].rstrip("%").rstrip(" %")) / 100
                        ov_style += [
                            ("TEXTCOLOR", (1, _i), (1, _i), _pass_color(_rate)),
                            ("FONTNAME",  (1, _i), (1, _i), "Helvetica-Bold"),
                        ]
                    except ValueError:
                        pass
            ov_tbl.setStyle(TableStyle(ov_style))
            story.append(ov_tbl)
            story.append(Spacer(1, 5 * mm))

            # ── Per-Category Results (OWASP LLM Top 10) ──────────────────────
            story.append(Paragraph("Per-Category Results (OWASP LLM Top 10)", H2))
            _active_rpts = {
                _bname: _r
                for _bname, _r in report.reports.items()
                if _bname not in report.skipped_backends
            }
            pcat_rows = [["Ref", "Description", "Winner", "Score", "Runner-up", "Score"]]
            for _ref in [f"LLM{_i:02d}" for _i in range(1, 11)]:
                _scores = sorted(
                    (
                        (_bname, _r.results_by_category.get(_ref, {}).get("pass_rate", 0.0))
                        for _bname, _r in _active_rpts.items()
                    ),
                    key=lambda _x: _x[1],
                    reverse=True,
                )
                _w = _scores[0][0] if _scores else "—"
                _ws = f"{_scores[0][1] * 100:.0f}%" if _scores else "—"
                _ru = _scores[1][0] if len(_scores) > 1 else "—"
                _rus = f"{_scores[1][1] * 100:.0f}%" if len(_scores) > 1 else "—"
                pcat_rows.append([_ref, _OWASP_LABELS.get(_ref, _ref), _w, _ws, _ru, _rus])
            pcat_tbl = Table(pcat_rows, colWidths=[14 * mm, 44 * mm, 35 * mm, 16 * mm, 35 * mm, 16 * mm])
            pcat_tbl.setStyle(TableStyle(_base_style(6)))
            story.append(pcat_tbl)
            story.append(Spacer(1, 5 * mm))

            # ── Content Moderation Results ────────────────────────────────────
            story.append(Paragraph("Content Moderation Results", H2))
            _CM_RANGES = {"Hate": (1, 5), "Violence": (6, 10), "Sexual": (11, 15), "Self-Harm": (16, 20)}

            def _cm_num(_pid: str):
                if _pid.startswith("CM-"):
                    try:
                        return int(_pid[3:])
                    except ValueError:
                        pass
                return None

            cm_rows = [["Backend", "Hate", "Violence", "Sexual", "Self-Harm", "Overall CM"]]
            for _b in report.backends_tested:
                _bval = _backend_str(_b)
                if _bval in report.skipped_backends:
                    cm_rows.append([_bval, "—", "—", "—", "—", "SKIPPED"])
                    continue
                _r = report.reports.get(_bval)
                if not _r:
                    continue
                _cm_prs = [_pr for _pr in _r.probe_results if _cm_num(_pr.probe.id) is not None]
                if not _cm_prs:
                    cm_rows.append([_bval, "—", "—", "—", "—", "—"])
                    continue
                _cats: Dict[str, str] = {}
                for _cn, (_lo, _hi) in _CM_RANGES.items():
                    _bkt = [_pr for _pr in _cm_prs if _lo <= (_cm_num(_pr.probe.id) or 0) <= _hi]
                    _cats[_cn] = (
                        f"{sum(1 for _pr in _bkt if _pr.passed is True) / len(_bkt) * 100:.0f}%"
                        if _bkt else "—"
                    )
                _cm_overall = f"{sum(1 for _pr in _cm_prs if _pr.passed is True) / len(_cm_prs) * 100:.0f}%"
                cm_rows.append([
                    _bval,
                    _cats["Hate"], _cats["Violence"], _cats["Sexual"], _cats["Self-Harm"],
                    _cm_overall,
                ])
            cm_tbl = Table(cm_rows, colWidths=[35 * mm, 18 * mm, 20 * mm, 18 * mm, 23 * mm, 22 * mm])
            cm_tbl.setStyle(TableStyle(_base_style(6)))
            story.append(cm_tbl)
            story.append(Spacer(1, 5 * mm))

            # ── Backend Capability Matrix ─────────────────────────────────────
            story.append(Paragraph("Backend Capability Matrix", H2))
            cap_rows = [
                ["Backend",              "Prompt Injection", "Jailbreak", "Content Mod.", "PII Detection", "Agentic Safety"],
                ["NeMo Guardrails",      "Primary",         "Yes",       "No",           "No",            "Yes"],
                ["GuardrailsAI",         "Yes",             "Yes",       "No",           "Yes",           "No"],
                ["Presidio",             "No",              "No",        "No",           "Primary",       "No"],
                ["Lakera Guard",         "Primary",         "Yes",       "No",           "No",            "No"],
                ["Custom HTTP",          "Yes",             "Yes",       "No",           "No",            "No"],
                ["OpenAI Moderation",    "No",              "Yes",       "Primary",      "No",            "No"],
                ["Azure Content Safety", "No",              "No",        "Primary",      "No",            "No"],
                ["Azure Prompt Shields", "Primary",         "Yes",       "No",           "No",            "No"],
                ["AWS Bedrock",          "Yes",             "Yes",       "Yes",          "No",            "No"],
                ["Llama Firewall",       "Primary",         "Yes",       "No",           "No",            "No"],
                ["LLM Guard",            "Yes",             "Yes",       "Yes",          "Yes",           "No"],
            ]
            cap_tbl = Table(cap_rows, colWidths=[36 * mm, 26 * mm, 20 * mm, 22 * mm, 22 * mm, 24 * mm])
            cap_tbl.setStyle(TableStyle(_base_style(6)))
            story.append(cap_tbl)
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("Primary = core strength  |  Yes = supported  |  No = not designed for this", BL))
            story.append(Spacer(1, 5 * mm))

            # ── Accuracy vs Latency Tradeoff ──────────────────────────────────
            story.append(Paragraph("Accuracy vs Latency Tradeoff", H2))
            _lat_sorted = sorted(
                (
                    (_bname, _r)
                    for _bname, _r in report.reports.items()
                    if _bname not in report.skipped_backends and _r.total_probes > 0
                ),
                key=lambda _x: _x[1].average_latency_ms,
            )
            lat_rows = [["Backend", "Overall %", "Avg Latency", "Latency Category", "Recommended For"]]
            for _bname, _r in _lat_sorted:
                _ms = _r.average_latency_ms
                if _ms < 10:
                    _lcat, _rec = "Ultra-fast", "Real-time, high-throughput pipelines"
                elif _ms < 200:
                    _lcat, _rec = "Fast", "Standard API protection"
                elif _ms < 1000:
                    _lcat, _rec = "Moderate", "Batch processing, async pipelines"
                else:
                    _lcat, _rec = "Slow", "Offline analysis, compliance audits"
                lat_rows.append([_bname, f"{_r.pass_rate * 100:.1f}%", f"{_ms:.0f} ms", _lcat, _rec])
            lat_tbl = Table(lat_rows, colWidths=[32 * mm, 20 * mm, 22 * mm, 24 * mm, 62 * mm])
            lat_tbl.setStyle(TableStyle(_base_style(5)))
            story.append(lat_tbl)
            story.append(Spacer(1, 5 * mm))

            # ── Notable Bypasses ──────────────────────────────────────────────
            story.append(Paragraph("Notable Bypasses", H2))
            _active_bnames = [
                _bname for _bname in report.reports
                if _bname not in report.skipped_backends
            ]
            _failed_on: Dict[str, set] = {}
            _probe_meta: Dict[str, Dict] = {}
            for _bname in _active_bnames:
                for _pr in report.reports[_bname].probe_results:
                    if _pr.passed is False:
                        _failed_on.setdefault(_pr.probe.id, set()).add(_bname)
                        _probe_meta[_pr.probe.id] = {
                            "owasp_ref": _pr.probe.owasp_ref,
                            "severity":  _pr.probe.severity,
                        }
            _n_active = len(_active_bnames)
            _bypass_groups: Dict[tuple, int] = {}
            for _pid, _bset in _failed_on.items():
                if len(_bset) == _n_active:
                    _m = _probe_meta[_pid]
                    _key = (_m["owasp_ref"], _m["severity"])
                    _bypass_groups[_key] = _bypass_groups.get(_key, 0) + 1
            if _bypass_groups:
                bypass_rows = [["OWASP Category", "Severity", "Count"]]
                for (_ref, _sev), _cnt in sorted(_bypass_groups.items()):
                    bypass_rows.append([_ref, _sev, str(_cnt)])
                bypass_tbl = Table(bypass_rows, colWidths=[55 * mm, 35 * mm, 25 * mm])
                bypass_tbl.setStyle(TableStyle(_base_style(3)))
                story.append(bypass_tbl)
            else:
                story.append(Paragraph(
                    "No universal bypasses detected — or probe results not available for this regenerated report.",
                    BL,
                ))
            story.append(Spacer(1, 5 * mm))

            # ── Backends Skipped This Month ───────────────────────────────────
            story.append(Paragraph("Backends Skipped This Month", H2))
            skip_rows = [["Backend", "Reason", "Expected In"]]
            if report.skipped_backends:
                for _bname, _reason in report.skipped_backends.items():
                    _exp = (
                        "Set GA_GUARD_API_URL"
                        if _reason == "CUSTOM_ENDPOINT_NOT_CONFIGURED"
                        else "Configure credentials"
                    )
                    skip_rows.append([_bname, _reason, _exp])
            else:
                skip_rows.append(["—", "—", "—"])
            skip_tbl = Table(skip_rows, colWidths=[40 * mm, 65 * mm, 60 * mm])
            skip_tbl.setStyle(TableStyle(_base_style(3)))
            story.append(skip_tbl)
            story.append(Spacer(1, 5 * mm))

            # ── Month-over-Month Changes ──────────────────────────────────────
            story.append(Paragraph("Month-over-Month Changes", H2))
            story.append(Paragraph(
                "First benchmark — no prior month comparison available.",
                BL,
            ))
            story.append(Spacer(1, 5 * mm))

            # ── How to Reproduce ──────────────────────────────────────────────
            story.append(Paragraph("How to Reproduce", H2))
            _yr = ts.year if hasattr(ts, "year") else "????"
            _mo = ts.month if hasattr(ts, "month") else "??"
            story.append(Paragraph(
                f"pip install guardrailprobe<br/>"
                f"guardrailprobe run --year {_yr} --month {_mo}<br/><br/>"
                f"Full guide: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md",
                BL,
            ))

        # Independence Statement
        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph("Independence Statement", H2))
        _independence_box = ParagraphStyle(
            "independence_box",
            parent=styles["Normal"],
            fontSize=8,
            leading=12,
            leftIndent=6 * mm,
            rightIndent=6 * mm,
            spaceBefore=3 * mm,
            spaceAfter=3 * mm,
            backColor=colors.Color(0.94, 0.94, 0.94),
            borderPadding=(4 * mm, 4 * mm, 4 * mm, 4 * mm),
        )
        story.append(Paragraph(
            "GuardrailProbe is independently operated with no commercial relationship "
            "to any tested backend provider.  All probes are open-source and methodology "
            "is publicly auditable.  Test results reflect backend configurations at the "
            "time of testing only.",
            _independence_box,
        ))

        _footer_text = (
            f"Generated by GuardrailProbe v{_VERSION}  |  "
            f"run_id: {run_id}  |  "
            "github.com/askuma/guardrailprobe"
        )
        _footer_style = ParagraphStyle(
            "page_footer",
            parent=styles["Normal"],
            fontSize=7,
            textColor=colors.Color(0.5, 0.5, 0.5),
            alignment=1,
        )

        def _draw_footer(canvas_obj, doc_obj):
            canvas_obj.saveState()
            p = Paragraph(_footer_text, _footer_style)
            p.wrap(doc_obj.width, 10 * mm)
            p.drawOn(canvas_obj, doc_obj.leftMargin, 8 * mm)
            canvas_obj.restoreState()

        doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)

    # ── PDF signing (pyhanko) ─────────────────────────────────────────────────

    def _sign_pdf(self, unsigned: Path, signed: Path) -> None:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # noqa: PLC0415
        from pyhanko.sign import fields as _fields  # noqa: PLC0415
        from pyhanko.sign import signers as _signers  # noqa: PLC0415
        from pyhanko.sign.timestamps import HTTPTimeStamper  # noqa: PLC0415

        signer = self._get_signer()
        sig_field_name = "Signature1"
        sig_box = (10, 10, 260, 60)

        def _attempt(use_tsa: bool) -> bytes:
            ts = HTTPTimeStamper(self._tsa_url) if use_tsa else None
            with open(unsigned, "rb") as inf:
                writer = IncrementalPdfFileWriter(inf)
                _fields.append_signature_field(
                    writer,
                    sig_field_spec=_fields.SigFieldSpec(
                        sig_field_name, on_page=0, box=sig_box
                    ),
                )
                meta = _signers.PdfSignatureMetadata(
                    field_name=sig_field_name,
                    reason="GuardrailProbe automated red-team report",
                    location="GuardrailProbe Platform",
                )
                out = _signers.sign_pdf(writer, meta, signer=signer, timestamper=ts)
                return out.getvalue()

        try:
            pdf_bytes = _attempt(use_tsa=True)
        except Exception as tsa_exc:
            logger.warning("TSA timestamp failed (%s) — signing without TSA", tsa_exc)
            pdf_bytes = _attempt(use_tsa=False)

        signed.write_bytes(pdf_bytes)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_signed_report(self, report: Any, output_path: str) -> str:
        """Build and sign a PDF report.

        Parameters
        ----------
        report:
            A RedTeamReport or ComparisonReport instance.
        output_path:
            Destination file path for the signed PDF.

        Returns
        -------
        str — the resolved output path.
        """
        out = Path(output_path)
        unsigned = out.with_suffix(".unsigned.pdf")
        try:
            self._build_pdf(report, unsigned)
            self._sign_pdf(unsigned, out)
        finally:
            if unsigned.exists():
                unsigned.unlink(missing_ok=True)

        sha256 = self._sha256(out)
        logger.info("Signed report written: %s  sha256=%s…", out, sha256[:16])
        return str(out)

    def verify_report(self, pdf_path: str) -> Dict[str, Any]:
        """Verify the embedded digital signature of a signed report PDF.

        Returns
        -------
        dict with keys:
            valid (bool)             — True iff signature is intact and cert trusted.
            signed_at (datetime|None)— RFC 3161 timestamp or signer-reported time.
            run_id (str|None)        — Extracted from PDF metadata.
        """
        from pyhanko.pdf_utils.reader import PdfFileReader  # noqa: PLC0415
        from pyhanko.sign.validation import validate_pdf_signature  # noqa: PLC0415
        from pyhanko_certvalidator import ValidationContext  # noqa: PLC0415

        path = Path(pdf_path)
        result: Dict[str, Any] = {"valid": False, "signed_at": None, "run_id": None}

        with open(path, "rb") as fh:
            r = PdfFileReader(fh)

            # Extract run_id from PDF info dict
            try:
                info_ref = r.trailer.get("/Info")
                if info_ref is not None:
                    info_obj = info_ref.get_object()
                    for key in ("/Subject", "/Keywords"):
                        raw = info_obj.get(key)
                        if raw is None:
                            continue
                        text = (
                            raw.decode("utf-8", errors="replace")
                            if isinstance(raw, (bytes, bytearray))
                            else str(raw)
                        )
                        m = re.search(r"run_id=([a-f0-9\-]{32,36})", text)
                        if m:
                            result["run_id"] = m.group(1)
                            break
            except Exception:
                pass

            sigs = r.embedded_signatures
            if not sigs:
                result["detail"] = "No embedded signatures found"
                return result

            try:
                vc = ValidationContext(allow_fetching=False)
                status = validate_pdf_signature(sigs[0], vc)
                result["valid"] = status.intact and status.valid
                dt = getattr(status, "timestamp_validity", None)
                if dt is None:
                    dt = getattr(status, "signer_reported_dt", None)
                if dt is not None:
                    result["signed_at"] = dt.astimezone(timezone.utc)
            except Exception as exc:
                result["valid"] = False
                result["detail"] = str(exc)

        return result
