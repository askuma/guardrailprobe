# Changelog

All notable changes to GuardrailProbe are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Fixed
- **NeMo — langchain dependency gap**: `nemoguardrails==0.22.0` requires
  `from langchain.chat_models import init_chat_model` but `langchain-aws>=1.6.1`
  no longer pulls in the `langchain` meta-package transitively. Added explicit
  `langchain>=0.3.0`, `langchain-openai>=0.2.0`, and `langchain-community>=0.3.0`
  to the `nemo` extra in `pyproject.toml` so the LangChain integration is always
  available after a clean install or Docker image rebuild.
- **NeMo — Bedrock ThrottlingException**: replaced the 3-second stagger gate
  (allowed 2 probes to overlap, causing 6 concurrent Bedrock API calls and
  exhausting Nova Pro's TPS quota) with `threading.Semaphore(1)`. Probes now run
  sequentially through Bedrock at ≤1 TPS; the 4s minimum-gap rate gate still
  applies for OpenRouter / OpenAI free-tier providers.
- **Dashboard — stuck "in progress" after container restart**: `_run_status` is
  an in-memory dict that is cleared on restart. The status endpoint now checks
  the latest saved benchmark on disk and returns `status: complete` when the
  requested `run_id` matches, so the polling loop exits cleanly. A JS safety-net
  also handles genuinely unknown run IDs (old sessions, different container) by
  calling `loadLatest()` and breaking the loop on HTTP 404.

### Added
- **NeMo — input-side fast triage**: `_NEMO_INPUT_BLOCK_RE` (34 regex patterns
  mirroring the colang policy literals) returns `BLOCK` in < 1 ms for exact
  attack-string matches, bypassing the LLM entirely for the majority of
  OWASP LLM01 / LLM06 probes.
- **NeMo — Ollama support** (`OLLAMA_BASE_URL`): local LLM as NeMo provider
  (priority 2, after `NEMO_OPENAI_API_KEY`). Uses `engine: openai` with Ollama's
  OpenAI-compatible `/v1` endpoint to avoid the deprecated
  `langchain_community.llms.Ollama` synchronous class. Disabled by default
  (`OLLAMA_BASE_URL=`) — CPU inference with llama3.2 is too slow (~20 s/probe)
  for NeMo's 3-call-per-probe flow; enable only when a GPU is available.
- **Docker — `network_mode: host`**: container shares the host network stack so
  `localhost:11434` (Ollama) is reachable without binding Ollama to `0.0.0.0`.
  Port mappings are implicit; the dashboard remains at `http://localhost:8080`.
- **NeMo LLM provider priority** (first match wins):
  1. `NEMO_OPENAI_API_KEY` — dedicated OpenAI key
  2. `OLLAMA_BASE_URL` — local inference (GPU recommended)
  3. AWS Bedrock (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`) — recommended for benchmarks; no per-minute rate limits; Semaphore(1) prevents TPS throttling
  4. `OPENROUTER_API_KEY` — free-tier (16 req/min)
  5. `OPENAI_API_KEY` — shared with OpenAI Moderation backend
  6. `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_ENDPOINT`
  7. `ANTHROPIC_API_KEY`
  8. (none) — colang pattern-matching only

### Changed
- `OLLAMA_MODEL` default changed from `llama3` → `llama3.2`.
- `OLLAMA_BASE_URL` default in `docker-compose.yml` changed from
  `http://localhost:11434` → `` (empty) so Bedrock takes priority when both
  AWS credentials and Ollama are present.

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
