# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** lakera (83.3% overall)
- **Best accuracy/latency ratio:** guardrails_ai
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 12
- **Backends skipped:** 3
- **Total probes run:** 624
- **Report generated:** 2026-06-25 15:01 UTC
- **Run ID:** 7cb895c9-2e2b-4def-ad4d-b88c5024400f

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 0.0% | — | LLM01 | LLM01 | 6 ms |
| guardrails_ai | 2.6% | — | LLM01 | LLM02 | 1 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 152 ms |
| lakera | 83.3% | — | LLM01 | LLM10 | 446 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 32333 ms |
| azure_content_safety | 25.6% | — | LLM02 | LLM01 | 465 ms |
| azure_prompt_shields | 25.3% | — | LLM01 | LLM09 | 460 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 402 ms |
| llama_firewall | SKIPPED (MISSING_CREDENTIALS) | — | — | — | — |
| llm_guard | SKIPPED (MISSING_CREDENTIALS) | — | — | — | — |
| ga_guard | SKIPPED (MISSING_CREDENTIALS) | — | — | — | — |
| custom_http | 85.9% | — | LLM01 | LLM10 | 0 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | lakera | 100% | openai_moderation | 100% |
| LLM02 | Insecure Output | lakera | 81% | custom_http | 81% |
| LLM03 | Training Data Poisoning | lakera | 100% | aws_bedrock | 100% |
| LLM04 | Model DoS | lakera | 67% | custom_http | 67% |
| LLM05 | Supply Chain | custom_http | 100% | lakera | 80% |
| LLM06 | Sensitive Info Disclosure | lakera | 100% | custom_http | 100% |
| LLM07 | Insecure Plugin | custom_http | 83% | lakera | 67% |
| LLM08 | Excessive Agency | lakera | 100% | custom_http | 100% |
| LLM09 | Overreliance | lakera | 100% | custom_http | 100% |
| LLM10 | Model Theft | lakera | 20% | custom_http | 20% |

---

## Content Moderation Results

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
| nemo | 0% | 0% | 0% | 0% | 0% |
| guardrails_ai | 0% | 0% | 0% | 0% | 0% |
| presidio | 0% | 0% | 0% | 0% | 0% |
| lakera | 100% | 100% | 100% | 100% | 100% |
| openai_moderation | 0% | 0% | 0% | 0% | 0% |
| azure_content_safety | 100% | 100% | 100% | 80% | 95% |
| azure_prompt_shields | 0% | 0% | 0% | 0% | 0% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |
| llama_firewall | — | — | — | — | SKIPPED |
| llm_guard | — | — | — | — | SKIPPED |
| ga_guard | — | — | — | — | SKIPPED |
| custom_http | 100% | 100% | 100% | 100% | 100% |

---

## Backend Capability Matrix

| Backend | Prompt Injection | Jailbreak | Content Moderation | PII Detection | Agentic Safety |
|---------|:---------------:|:---------:|:------------------:|:-------------:|:--------------:|
| NeMo Guardrails | ✓ Primary | ✓ | ✗ | ✗ | ✓ |
| GuardrailsAI | ✓ | ✓ | ✗ | ✓ | ✗ |
| Presidio | ✗ | ✗ | ✗ | ✓ Primary | ✗ |
| Lakera Guard | ✓ Primary | ✓ | ✗ | ✗ | ✗ |
| Custom HTTP | ✓ | ✓ | ✗ | ✗ | ✗ |
| OpenAI Moderation | ✗ | ✓ | ✓ Primary | ✗ | ✗ |
| Azure Content Safety | ✗ | ✗ | ✓ Primary | ✗ | ✗ |
| Azure Prompt Shields | ✓ Primary | ✓ | ✗ | ✗ | ✗ |
| AWS Bedrock | ✓ | ✓ | ✓ | ✗ | ✗ |
| Llama Firewall | ✓ Primary | ✓ | ✗ | ✗ | ✗ |
| LLM Guard | ✓ | ✓ | ✓ | ✓ | ✗ |

> ✓ Primary = core strength, ✓ = supported, ✗ = not designed for this

---

## Accuracy vs Latency Tradeoff

| Backend | Overall % | Avg Latency | Latency Category | Recommended For |
|---------|:---------:|:-----------:|:----------------:|-----------------|
| custom_http | 85.9% | 0 ms | Ultra-fast | Real-time, high-throughput pipelines |
| guardrails_ai | 2.6% | 1 ms | Ultra-fast | Real-time, high-throughput pipelines |
| nemo | 0.0% | 6 ms | Ultra-fast | Real-time, high-throughput pipelines |
| presidio | 6.4% | 152 ms | Fast | Standard API protection |
| aws_bedrock | 59.0% | 402 ms | Moderate | Batch processing, async pipelines |
| lakera | 83.3% | 446 ms | Moderate | Batch processing, async pipelines |
| azure_prompt_shields | 25.3% | 460 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 25.6% | 465 ms | Moderate | Batch processing, async pipelines |
| openai_moderation | 100.0% | 32333 ms | Slow | Offline analysis, compliance audits |

---

## Notable Bypasses

| OWASP Category | Severity | Count |
|:---------------|:--------:|:-----:|
| LLM04 | high | 1 |
| LLM04 | medium | 1 |
| LLM10 | high | 3 |
| LLM10 | medium | 1 |

---

## Backends Skipped This Month

| Backend | Reason | Expected In |
|---------|--------|-------------|
| llama_firewall | MISSING_CREDENTIALS | Configure credentials |
| llm_guard | MISSING_CREDENTIALS | Configure credentials |
| ga_guard | MISSING_CREDENTIALS | Configure credentials |

---

## Month-over-Month Changes

First benchmark — no prior month comparison available.

---

## How to Reproduce

```bash
pip install guardrailprobe
guardrailprobe run --year 2026 --month 6
```

Full guide: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

*GuardrailProbe v0.1.0 — independent, open-source, not affiliated with any tested vendor.*
