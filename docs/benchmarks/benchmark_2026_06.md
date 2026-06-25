# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** lakera (83.3% overall)
- **Best accuracy/latency ratio:** azure_prompt_shields
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 8
- **Backends skipped:** 0
- **Total probes run:** 547
- **Report generated:** 2026-06-25 09:40 UTC
- **Run ID:** 2ee4d9dd-af6c-4fa9-b786-16db01a4bce8

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 0.0% | — | LLM01 | LLM01 | 220 ms |
| guardrails_ai | 2.6% | — | LLM01 | LLM02 | 103 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 210 ms |
| lakera | 83.3% | — | LLM01 | LLM10 | 408 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 34500 ms |
| azure_content_safety | 25.6% | — | LLM02 | LLM01 | 412 ms |
| azure_prompt_shields | 85.9% | — | LLM01 | LLM10 | 384 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 763 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | lakera | 100% | openai_moderation | 100% |
| LLM02 | Insecure Output | lakera | 81% | azure_prompt_shields | 81% |
| LLM03 | Training Data Poisoning | lakera | 100% | azure_prompt_shields | 100% |
| LLM04 | Model DoS | lakera | 67% | azure_prompt_shields | 67% |
| LLM05 | Supply Chain | azure_prompt_shields | 100% | lakera | 80% |
| LLM06 | Sensitive Info Disclosure | lakera | 100% | azure_prompt_shields | 100% |
| LLM07 | Insecure Plugin | azure_prompt_shields | 83% | lakera | 67% |
| LLM08 | Excessive Agency | lakera | 100% | azure_prompt_shields | 100% |
| LLM09 | Overreliance | lakera | 100% | azure_prompt_shields | 100% |
| LLM10 | Model Theft | lakera | 20% | azure_prompt_shields | 20% |

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
| azure_prompt_shields | 100% | 100% | 100% | 100% | 100% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |

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
| guardrails_ai | 2.6% | 103 ms | Fast | Standard API protection |
| presidio | 6.4% | 210 ms | Moderate | Batch processing, async pipelines |
| nemo | 0.0% | 220 ms | Moderate | Batch processing, async pipelines |
| azure_prompt_shields | 85.9% | 384 ms | Moderate | Batch processing, async pipelines |
| lakera | 83.3% | 408 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 25.6% | 412 ms | Moderate | Batch processing, async pipelines |
| aws_bedrock | 59.0% | 763 ms | Moderate | Batch processing, async pipelines |
| openai_moderation | 100.0% | 34500 ms | Slow | Offline analysis, compliance audits |

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
