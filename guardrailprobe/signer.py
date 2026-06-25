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
import importlib.util
import logging
import os
import re

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("ReportSigner")

_PYHANKO_AVAILABLE  = importlib.util.find_spec("pyhanko")   is not None
_REPORTLAB_AVAILABLE = importlib.util.find_spec("reportlab") is not None

_VERSION = "0.1.0"


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
            # Comparison tables
            story.append(Paragraph("Backend Comparison Summary", H2))
            comp_rows = [["Backend", "Total", "Passed", "Failed", "Pass %", "Avg ms"]]
            for b in report.backends_tested:
                bval = _backend_str(b)
                r = report.reports.get(bval)
                if not r:
                    continue
                comp_rows.append([
                    bval,
                    str(r.total_probes),
                    str(r.passed),
                    str(r.failed),
                    f"{r.pass_rate * 100:.1f}%",
                    f"{r.average_latency_ms:.0f}",
                ])
            comp_tbl = Table(comp_rows, colWidths=[38 * mm, 18 * mm, 18 * mm, 18 * mm, 18 * mm, 20 * mm])
            comp_tbl.setStyle(TableStyle(_base_style(6)))
            story.append(comp_tbl)
            story.append(Spacer(1, 4 * mm))

            story.append(Paragraph("Category Winners", H2))
            winner_rows = [["Ref", "Category", "Winner"]]
            tie_footnotes = []
            for ref in sorted(report.category_winners.keys()):
                info = report.category_winners[ref]
                winner_name = info["winner"].replace("_", " ")
                if info.get("tiebreaker") == "latency" and len(info.get("tied_backends", [])) > 1:
                    winner_rows.append([ref, _OWASP_LABELS.get(ref, ref), f"{winner_name}*"])
                    tie_footnotes.append(
                        f"* {ref}: Tiebreaker by latency — "
                        f"{winner_name} ({info['winner_latency_ms']} ms) wins among: "
                        + ", ".join(b.replace("_", " ") for b in info["tied_backends"])
                    )
                else:
                    winner_rows.append([ref, _OWASP_LABELS.get(ref, ref), winner_name])
            winner_tbl = Table(winner_rows, colWidths=[16 * mm, 60 * mm, 60 * mm])
            winner_tbl.setStyle(TableStyle(_base_style(3)))
            story.append(winner_tbl)
            if tie_footnotes:
                story.append(Spacer(1, 2 * mm))
                for note in tie_footnotes:
                    story.append(Paragraph(note, BL))

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
