# guardrailprobe

**Provider-agnostic AI guardrail benchmarking tool.**
Tests your guardrail layer — not your model — across 11 backends against the OWASP LLM Top 10.

[![CI](https://github.com/askuma/guardrailprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/askuma/guardrailprobe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/guardrailprobe)](https://pypi.org/project/guardrailprobe/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/guardrailprobe)](https://pypi.org/project/guardrailprobe/)

---

## What it does

`guardrailprobe` fires 78 attack probes at your guardrail endpoints and tells you which ones let attacks through. It produces:

- **Pass/fail per probe** across OWASP LLM01–LLM10 and content-moderation categories
- **Side-by-side comparison** of multiple backends in a single run
- **Signed benchmark reports** (PDF with RFC 3161 timestamp, JSON, Markdown)
- **Flask dashboard** for ad-hoc probe runs and report browsing

No framework lock-in. No cloud account required. Just point it at an endpoint and run.

---

## Supported backends

| Backend | Adapter key | Notes |
|---|---|---|
| NVIDIA NeMo Guardrails | `nemo` | Requires `pip install guardrailprobe[nemo]` |
| Guardrails AI | `guardrails_ai` | Regex fallback always available; SDK optional |
| Microsoft Presidio | `presidio` | Requires `pip install guardrailprobe[presidio]` |
| Lakera Guard | `lakera` | Requires `LAKERA_GUARD_API_KEY` |
| OpenAI Moderation | `openai_moderation` | Requires `OPENAI_API_KEY` |
| Azure Content Safety | `azure_content_safety` | Requires `AZURE_CONTENT_SAFETY_KEY` + endpoint |
| Azure Prompt Shields | `azure_prompt_shields` | Requires `AZURE_PROMPT_SHIELDS_KEY` + endpoint |
| AWS Bedrock Guardrails | `aws_bedrock` | Requires `AWS_ACCESS_KEY_ID` + guardrail ID |
| Meta LlamaFirewall | `llama_firewall` | Requires `pip install guardrailprobe[llamafirewall]` |
| LLM Guard | `llm_guard` | Requires `pip install guardrailprobe[llm_guard]` |
| Custom HTTP | `custom_http` | Generic HTTPS endpoint via `GA_GUARD_API_URL` |

Adapters with missing credentials return `SKIPPED` gracefully — partial configurations run fine.

---

## Installation

```bash
pip install guardrailprobe
```

With optional SDK extras:

```bash
# All extras
pip install "guardrailprobe[all]"

# Pick what you need
pip install "guardrailprobe[nemo,guardrails_ai,presidio]"
```

Skip the spaCy model download (e.g. in CI):

```bash
GUARDRAILPROBE_SKIP_SPACY=1 pip install guardrailprobe
```

---

## Quick start

```bash
# 1. Set up credentials
guardrailprobe init

# 2. Check which backends are ready
guardrailprobe status

# 3. Run a benchmark (current month, all configured backends)
guardrailprobe run --output-dir ./reports

# 4. Run against specific backends only
guardrailprobe run --backends lakera,openai_moderation --output-dir ./reports

# 5. Launch the dashboard
guardrailprobe dashboard
```

---

## Probes

78 built-in attack probes across 11 categories:

| Category | OWASP ref | Probes |
|---|---|---|
| Prompt Injection | LLM01 | 7 |
| Insecure Output Handling | LLM02 | 6 |
| Training Data Poisoning | LLM03 | 5 |
| Model Denial of Service | LLM04 | 6 |
| Supply Chain Vulnerabilities | LLM05 | 5 |
| Sensitive Info Disclosure | LLM06 | 7 |
| Insecure Plugin Design | LLM07 | 6 |
| Excessive Agency | LLM08 | 6 |
| Overreliance | LLM09 | 5 |
| Model Theft | LLM10 | 5 |
| Content Moderation | CM-001–020 | 20 |
| **Total** | | **78** |

See [METHODOLOGY.md](METHODOLOGY.md) for probe design, scoring, and reproduction steps.

---

## Reports

Each `guardrailprobe run` produces three artifacts in the output directory:

```
reports/
  benchmark_2026_06.pdf   # Signed PDF with RFC 3161 timestamp
  benchmark_2026_06.json  # Machine-readable full results
  benchmark_2026_06.md    # Human-readable summary
```

To sign reports with your own certificate:

```bash
guardrailprobe cert generate          # self-signed P12 for testing
guardrailprobe cert show              # inspect the active signing cert
guardrailprobe cert verify report.pdf # verify an existing report
```

Set `GUARDRAIL_SIGNING_KEY_P12` to the path of your P12 file.

---

## Configuration

Copy `.env.example` to `.env` and fill in credentials for the backends you want to test:

```bash
cp .env.example .env
```

Key variables:

| Variable | Backend |
|---|---|
| `LAKERA_GUARD_API_KEY` | Lakera Guard |
| `OPENAI_API_KEY` | OpenAI Moderation |
| `AZURE_CONTENT_SAFETY_KEY` + `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure Content Safety |
| `AZURE_PROMPT_SHIELDS_KEY` + `AZURE_PROMPT_SHIELDS_ENDPOINT` | Azure Prompt Shields |
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_GUARDRAIL_ID` + `AWS_GUARDRAIL_VERSION` | AWS Bedrock |
| `GA_GUARD_API_URL` | Custom HTTPS endpoint |
| `GUARDRAIL_SIGNING_KEY_P12` | PDF signing certificate path |

---

## Python API

```python
from guardrailprobe import GuardrailBackend
from guardrailprobe.runner import RedTeamRunner
from guardrailprobe.probes import ProbeLibrary, AttackCategory

runner = RedTeamRunner()
library = ProbeLibrary()

# Run all probes against one backend
report = runner.run(GuardrailBackend.LAKERA, library.all_probes())
print(f"Pass rate: {report.pass_rate:.1%}")

# Compare backends
comparison = runner.compare_backends(
    [GuardrailBackend.LAKERA, GuardrailBackend.OPENAI_MODERATION],
    library.all_probes(),
)
print(f"Best overall: {comparison.best_overall}")

# Filter probes
injection_probes = library.get_by_category(AttackCategory.PROMPT_INJECTION)
critical_probes  = library.get_by_severity("critical")
cm_probes        = library.get_content_moderation_probes()
```

---

## Development

```bash
GUARDRAILPROBE_SKIP_SPACY=1 pip install -e ".[dev]"
pytest tests/ -v
ruff check guardrailprobe/ tests/
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
