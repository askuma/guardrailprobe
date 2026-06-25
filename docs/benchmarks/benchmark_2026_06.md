# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** nemo (85.9% overall)
- **Best accuracy/latency ratio:** llama_firewall
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 10
- **Backends skipped:** 0
- **Total probes run:** 703
- **Report generated:** 2026-06-24 12:32 UTC
- **Run ID:** aaf34a3a-b850-4085-b01a-4fbcd70983ee

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 85.9% | — | LLM01 | LLM10 | 916 ms |
| guardrails_ai | 2.6% | — | LLM07 | LLM01 | 87 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 1025 ms |
| lakera | 83.3% | — | LLM01 | LLM10 | 458 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 34453 ms |
| azure_content_safety | 25.6% | — | LLM02 | LLM01 | 718 ms |
| azure_prompt_shields | 24.4% | — | LLM01 | LLM09 | 1534 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 807 ms |
| llama_firewall | 85.9% | — | LLM01 | LLM10 | 51 ms |
| llm_guard | 85.9% | — | LLM01 | LLM10 | 207 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | nemo | 100% | lakera | 100% |
| LLM02 | Insecure Output | nemo | 81% | lakera | 81% |
| LLM03 | Training Data Poisoning | nemo | 100% | lakera | 100% |
| LLM04 | Model DoS | nemo | 67% | lakera | 67% |
| LLM05 | Supply Chain | nemo | 100% | llama_firewall | 100% |
| LLM06 | Sensitive Info Disclosure | nemo | 100% | lakera | 100% |
| LLM07 | Insecure Plugin | nemo | 83% | llama_firewall | 83% |
| LLM08 | Excessive Agency | nemo | 100% | lakera | 100% |
| LLM09 | Overreliance | nemo | 100% | lakera | 100% |
| LLM10 | Model Theft | nemo | 20% | lakera | 20% |

---

## Content Moderation Results

These probes test content moderation capabilities separate from adversarial attack detection.
Backends designed for content moderation (Azure Content Safety, OpenAI Moderation) are
expected to score higher here than on OWASP probes.

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
| nemo | 100% | 100% | 100% | 100% | 100% |
| guardrails_ai | 0% | 0% | 0% | 0% | 0% |
| presidio | 0% | 0% | 0% | 0% | 0% |
| lakera | 100% | 100% | 100% | 100% | 100% |
| openai_moderation | 0% | 0% | 0% | 0% | 0% |
| azure_content_safety | 100% | 100% | 100% | 80% | 95% |
| azure_prompt_shields | 0% | 0% | 0% | 0% | 0% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |
| llama_firewall | 100% | 100% | 100% | 100% | 100% |
| llm_guard | 100% | 100% | 100% | 100% | 100% |

---

## Backend Capability Matrix

Use this matrix to understand what each backend is designed to detect. A low OWASP score
does not mean a backend is poor — it may be optimized for a different threat category.

| Backend | Prompt Injection | Jailbreak | Content Moderation | PII Detection | Hallucination | Agentic Safety |
|---------|:---------------:|:---------:|:------------------:|:-------------:|:-------------:|:--------------:|
| NeMo Guardrails | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✓ |
| GuardrailsAI | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ |
| Presidio | ✗ | ✗ | ✗ | ✓ Primary | ✗ | ✗ |
| Lakera Guard | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✗ |
| OpenAI Moderation | ✗ | ✓ | ✓ Primary | ✗ | ✗ | ✗ |
| Azure Content Safety | ✗ | ✗ | ✓ Primary | ✗ | ✗ | ✗ |
| Azure Prompt Shields | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✗ |
| AWS Bedrock | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| LlamaFirewall | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✓ |
| LLM Guard | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ |
| Custom HTTP | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |

> ✓ Primary = this is the backend's core strength
> ✓ = supported capability
> ✗ = not designed for this threat category

---

## Accuracy vs Latency Tradeoff

Key insight: high accuracy and low latency are in tension. Choose your backend based on
your latency budget.

| Backend | Overall % | Avg Latency | Latency Category | Recommended For |
|---------|:---------:|:-----------:|:----------------:|-----------------|
| llama_firewall | 85.9% | 51 ms | Fast | Standard API protection |
| guardrails_ai | 2.6% | 87 ms | Fast | Standard API protection |
| llm_guard | 85.9% | 207 ms | Moderate | Batch processing, async pipelines |
| lakera | 83.3% | 458 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 25.6% | 718 ms | Moderate | Batch processing, async pipelines |
| aws_bedrock | 59.0% | 807 ms | Moderate | Batch processing, async pipelines |
| nemo | 85.9% | 916 ms | Moderate | Batch processing, async pipelines |
| presidio | 6.4% | 1025 ms | Slow | Offline analysis, compliance audits |
| azure_prompt_shields | 24.4% | 1534 ms | Slow | Offline analysis, compliance audits |
| openai_moderation | 100.0% | 34453 ms | Slow | Offline analysis, compliance audits |

Latency categories:
- Fast: <200ms         (LlamaFirewall, GuardrailsAI, LLM Guard)
- Moderate: 200-1000ms (Lakera, Azure Content Safety, AWS Bedrock, NeMo)
- Slow: 1000ms+        (Presidio, Azure Prompt Shields, OpenAI Moderation)

---

## Notable Bypasses

Attack patterns that bypassed ALL tested backends this month. These represent current gaps
in the guardrail ecosystem.

| OWASP Category | Severity | Count |
|:---------------|:--------:|:-----:|
| LLM04 | high | 1 |
| LLM04 | medium | 1 |
| LLM10 | high | 3 |
| LLM10 | medium | 1 |

> Full probe payloads are available to verified security researchers. Open an issue with
> label "researcher-access" to request access.

---

## Backends Skipped This Month

| Backend | Reason | Expected In |
|---------|--------|-------------|
| — | — | — |

---

## Month-over-Month Changes

First benchmark — no prior month comparison available.

---

## How to Reproduce This Benchmark

```bash
pip install guardrailprobe
cp .env.example .env
# edit .env with credentials
guardrailprobe run --year 2026 --month 6 --output-dir ./my-results
```

Full reproduction guide: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## About This Benchmark

GuardrailProbe is an independent, open-source AI guardrail testing framework with no
commercial relationship to any tested backend.

Probe library, methodology, and scoring logic are fully open source and independently
auditable.

- GitHub: github.com/askuma/guardrailprobe
- PyPI: pypi.org/project/guardrailprobe
- Methodology: METHODOLOGY.md
- Report an issue: GitHub Issues

---
*GuardrailProbe is not affiliated with NVIDIA, Microsoft, OpenAI, Lakera, Meta, Protect AI,
or Amazon. Results reflect probe library v0.1.0 against backend configurations at time
of testing.*
