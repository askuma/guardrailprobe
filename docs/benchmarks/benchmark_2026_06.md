# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** nemo (85.9% overall)
- **Best accuracy/latency ratio:** guardrails_ai
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 10
- **Backends skipped:** 0
- **Total probes run:** 624
- **Report generated:** 2026-06-25 17:56 UTC
- **Run ID:** 20b24ec7-4528-4311-af0b-9b5acf279797

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 85.9% | — | LLM01 | LLM10 | 1046 ms |
| lakera | 83.3% | — | LLM01 | LLM10 | 474 ms |
| azure_content_safety | 25.6% | — | LLM02 | LLM01 | 505 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 391 ms |
| llama_firewall | 0.0% | — | — | — | 0 ms |
| llm_guard | 35.9% | — | LLM01 | LLM02 | 642 ms |
| guardrails_ai | 2.6% | — | LLM01 | LLM05 | 0 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 788 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 34826 ms |
| azure_prompt_shields | 25.3% | — | LLM01 | LLM09 | 517 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | nemo | 100% | lakera | 100% |
| LLM02 | Insecure Output | nemo | 81% | lakera | 81% |
| LLM03 | Training Data Poisoning | nemo | 100% | lakera | 100% |
| LLM04 | Model DoS | nemo | 67% | lakera | 67% |
| LLM05 | Supply Chain | nemo | 100% | lakera | 80% |
| LLM06 | Sensitive Info Disclosure | nemo | 100% | lakera | 100% |
| LLM07 | Insecure Plugin | nemo | 83% | lakera | 67% |
| LLM08 | Excessive Agency | nemo | 100% | lakera | 100% |
| LLM09 | Overreliance | nemo | 100% | lakera | 100% |
| LLM10 | Model Theft | nemo | 20% | lakera | 20% |

---

## Content Moderation Results

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
| nemo | 100% | 100% | 100% | 100% | 100% |
| lakera | 100% | 100% | 100% | 100% | 100% |
| azure_content_safety | 100% | 100% | 100% | 80% | 95% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |
| llama_firewall | 0% | 0% | 0% | 0% | 0% |
| llm_guard | 0% | 0% | 0% | 60% | 15% |
| guardrails_ai | 0% | 0% | 0% | 0% | 0% |
| presidio | 0% | 0% | 0% | 0% | 0% |
| openai_moderation | 0% | 0% | 0% | 0% | 0% |
| azure_prompt_shields | 0% | 0% | 0% | 0% | 0% |

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
| guardrails_ai | 2.6% | 0 ms | Ultra-fast | Real-time, high-throughput pipelines |
| aws_bedrock | 59.0% | 391 ms | Moderate | Batch processing, async pipelines |
| lakera | 83.3% | 474 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 25.6% | 505 ms | Moderate | Batch processing, async pipelines |
| azure_prompt_shields | 25.3% | 517 ms | Moderate | Batch processing, async pipelines |
| llm_guard | 35.9% | 642 ms | Moderate | Batch processing, async pipelines |
| presidio | 6.4% | 788 ms | Moderate | Batch processing, async pipelines |
| nemo | 85.9% | 1046 ms | Slow | Offline analysis, compliance audits |
| openai_moderation | 100.0% | 34826 ms | Slow | Offline analysis, compliance audits |

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
| — | — | — |

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
