# guardrailprobe

**Provider-agnostic AI guardrail benchmarking tool.**
Tests your guardrail layer — not your model — across 11 backends against the OWASP LLM Top 10.

[![CI](https://github.com/askuma/guardrailprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/askuma/guardrailprobe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/guardrailprobe)](https://pypi.org/project/guardrailprobe/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/guardrailprobe)](https://pypi.org/project/guardrailprobe/)
[![Probes](https://img.shields.io/badge/probes-78-22c55e)](METHODOLOGY.md)
[![Backends](https://img.shields.io/badge/backends-12-0ea5e9)](#supported-backends)

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
| Azure Prompt Shields | `azure_prompt_shields` | Shares credentials with `azure_content_safety` — no separate key |
| AWS Bedrock Guardrails | `aws_bedrock` | Requires `AWS_ACCESS_KEY_ID` + guardrail ID |
| Meta LlamaFirewall | `llama_firewall` | Requires `pip install guardrailprobe[llamafirewall]` |
| LLM Guard | `llm_guard` | Requires `pip install guardrailprobe[llm_guard]` |
| GA Guard | `ga_guard` | Requires `GA_GUARD_API_URL` (must be `https://`) |

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
# 1. Set up credentials — interactive wizard (or copy .env.example to .env and edit manually)
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

## Docker

### Start the dashboard

```bash
docker compose up
```

Open http://localhost:8080. The container starts even without a `.env` file — the **Setup Guide** card in the dashboard lists exactly which environment variables each unready adapter needs.

### Configure credentials

```bash
cp .env.example .env
# Fill in the keys for the backends you want to test, then:
docker compose up
```

The `.env` file is optional. Any variables already exported in your shell are passed through automatically via the `environment:` block in `docker-compose.yml`.

### Adapter status in Docker

The Docker image bundles the SDKs for most adapters. Here is the out-of-the-box status and what you need to enable each one:

| Adapter | SDK bundled | What you need |
|---|---|---|
| `guardrails_ai` | Yes | Nothing — works without credentials (regex fallback) |
| `presidio` | Yes | Nothing — runs locally |
| `nemo` | Yes | One LLM key: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, or `AZURE_OPENAI_API_KEY` |
| `aws_bedrock` | Yes (`boto3`) | `AWS_BEDROCK_GUARDRAIL_ID`, `AWS_DEFAULT_REGION`, AWS credentials |
| `lakera` | Yes | `LAKERA_GUARD_API_KEY` |
| `openai_moderation` | Yes | `OPENAI_API_KEY` |
| `azure_content_safety` | Yes | `AZURE_CONTENT_SAFETY_KEY` + `AZURE_CONTENT_SAFETY_ENDPOINT` |
| `azure_prompt_shields` | Yes | Same as `azure_content_safety` |
| `ga_guard` | Yes | `GA_GUARD_API_URL` (must be `https://`) |
| `llama_firewall` | No — volume-mounted | See below |
| `llm_guard` | No — volume-mounted | See below |

### LlamaFirewall (Meta PromptGuard 2)

LlamaFirewall runs a local ML model and is excluded from the Docker image to keep it lean.

**Requirements:** Python 3.10–3.12 on the host (PyTorch is a transitive dependency).

```bash
# 1. Install into ./site-packages on your host
pip install llamafirewall --target ./site-packages

# 2. Restart the container — the entrypoint detects the package automatically
docker compose up
```

On startup you will see:

```
[guardrailprobe] site-packages mounted — llama_firewall: YES  llm_guard: NO
```

No environment variables are required. LlamaFirewall runs fully offline.

---

### LLM Guard (Protect AI)

LLM Guard runs PromptInjection and Toxicity scanners locally and is also excluded from the Docker image.

**Requirements:** Python 3.9–3.12 on the host.

```bash
# 1. Install into ./site-packages on your host
pip install llm-guard --target ./site-packages

# 2. Restart the container
docker compose up
```

On startup you will see:

```
[guardrailprobe] site-packages mounted — llama_firewall: NO  llm_guard: YES
```

No environment variables are required. LLM Guard runs fully offline.

---

### Install both at once

```bash
pip install llamafirewall llm-guard --target ./site-packages
docker compose up
```

The container prints the detected status for each package at startup and skips any that are absent — no configuration required.

---

### GA Guard endpoint

Point the `ga_guard` backend at your GA Guard (or any HTTPS guardrail) API:

| Variable | Required | Description |
|---|---|---|
| `GA_GUARD_API_URL` | **Yes** | Target endpoint — must start with `https://` |
| `GA_GUARD_API_KEY` | No | Bearer token or API key |
| `GA_GUARD_AUTH_HEADER` | No | Header name for the key (default: `Authorization`) |

Add to `.env`:

```bash
GA_GUARD_API_URL=https://your-guardrail-api.example.com/check
GA_GUARD_API_KEY=your-key-here
# GA_GUARD_AUTH_HEADER=X-Api-Key   # only needed if the API uses a non-standard header
```

### One-shot benchmark via Docker

```bash
docker compose run --rm guardrailprobe \
  guardrailprobe run --year 2026 --month 6 --output-dir /app/reports
```

Reports are written to the `guardrailprobe_reports` named volume and also to `./docs/benchmarks` on the host (via the `./docs` bind mount).

### Skip the spaCy model download (CI / constrained environments)

```bash
docker compose build --build-arg SKIP_SPACY=1
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

Choose either approach — both produce the same `.env` file.

### Option A — Interactive wizard (recommended)

```bash
guardrailprobe init
```

Walks through each backend and prompts for keys. Press **Enter** to skip any adapter you don't have credentials for. Writes only what you enter to `.env`.

### Option B — Edit manually

```bash
cp .env.example .env
# Open .env and fill in the keys for the backends you want to test
```

---

### Key variables

| Variable | Backend |
|---|---|
| `LAKERA_GUARD_API_KEY` | Lakera Guard |
| `OPENAI_API_KEY` | OpenAI Moderation (also used by NeMo) |
| `AZURE_CONTENT_SAFETY_ENDPOINT` + `AZURE_CONTENT_SAFETY_KEY` | Azure Content Safety **and** Azure Prompt Shields |
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | AWS Bedrock (or use an IAM role / `aws configure`) |
| `AWS_BEDROCK_GUARDRAIL_ID` + `AWS_DEFAULT_REGION` | AWS Bedrock — guardrail ID and region |
| `GA_GUARD_API_URL` | GA Guard / any HTTPS guardrail endpoint |
| `GA_GUARD_API_KEY` | GA Guard — optional API key |
| `GUARDRAIL_SIGNING_KEY_P12` | PDF signing certificate path |

After either option, verify which backends are ready:

```bash
guardrailprobe status
```

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
