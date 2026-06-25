# Changelog

All notable changes to GuardrailProbe are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.0] — 2026-06-25

Initial public release. Standalone spin-off from guardrail_framework_complete
with zero dependency on the guardrail-framework package.

### Added
- 11 self-contained adapters: NeMo, GuardrailsAI, Presidio, Lakera, OpenAI Moderation,
  Azure Content Safety, Azure Prompt Shields, AWS Bedrock, Llama Firewall, LLM Guard,
  Custom HTTP
- `AdapterRegistry` singleton with `status_report()`, `all()`, `names()`
- `ProbeResponse` and `AdapterStatus` types with no external framework dependency
- 78 built-in attack probes: OWASP LLM01–LLM10 (5–7 per category) + CM-001–CM-020
- `RedTeamRunner` and `BenchmarkRunner` (no GuardrailFramework argument)
- `ReportSigner`: signed PDF (pyhanko + RFC 3161 timestamp), JSON, and Markdown output
- `guardrailprobe run` — monthly benchmark runner
- `guardrailprobe status` — adapter credential readiness table
- `guardrailprobe init` — interactive first-run wizard writing credentials to `.env`
- `guardrailprobe cert` — `generate`, `show`, `verify` subcommands
- `guardrailprobe dashboard` — Flask single-page UI at localhost:8080
- `hatch_build.py` post-install hook for `en_core_web_lg` spaCy model
  (skip via `GUARDRAILPROBE_SKIP_SPACY=1`)
- `Dockerfile` and `docker-compose.yml` for containerised deployment
- CI matrix: Python 3.10 / 3.11 / 3.12, ruff, pytest

### Security
- `CustomHTTPAdapter` enforces HTTPS-only URLs and blocks private IP ranges (SSRF prevention)
- OpenAI adapter includes 70-second quota circuit breaker and 5-retry 429 handling
