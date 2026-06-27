# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** llama_firewall (85.9% overall)
- **Best accuracy/latency ratio:** llm_guard
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 10
- **Backends skipped:** 0
- **Total probes run:** 684
- **Report generated:** 2026-06-27 17:20 UTC
- **Run ID:** 7e927d25-14fa-444a-9279-faf2796650ea

> **Note — NeMo latency**: the 29 607 ms average reported here reflects a run where
> the `langchain` package was missing from the Docker image, causing each non-fast-path
> probe to hit the 30 s asyncio timeout. The `langchain>=0.3.0` dependency was added
> in the same session (commit `5058629`). With the fix applied, NeMo latency on AWS
> Bedrock (Nova Pro, `Semaphore(1)`) is ~3–7 s per probe. A new benchmark run with
> the corrected image will supersede this measurement.

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 83.3% | — | LLM01 | LLM10 | 29607 ms ⚠️ |
| lakera | 83.3% | — | LLM01 | LLM10 | 572 ms |
| azure_content_safety | 25.6% | — | LLM02 | LLM01 | 570 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 420 ms |
| llama_firewall | 85.9% | — | LLM01 | LLM10 | 1010 ms |
| llm_guard | 80.0% | — | LLM03 | LLM10 | 0 ms |
| guardrails_ai | 2.6% | — | LLM01 | LLM02 | 374 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 1153 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 33648 ms |
| azure_prompt_shields | 24.4% | — | LLM01 | LLM09 | 582 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | nemo | 100% | lakera | 100% |
| LLM02 | Insecure Output | nemo | 81% | lakera | 81% |
| LLM03 | Training Data Poisoning | nemo | 100% | lakera | 100% |
| LLM04 | Model DoS | lakera | 67% | llama_firewall | 67% |
| LLM05 | Supply Chain | nemo | 100% | llama_firewall | 100% |
| LLM06 | Sensitive Info Disclosure | nemo | 100% | lakera | 100% |
| LLM07 | Insecure Plugin | nemo | 83% | llama_firewall | 83% |
| LLM08 | Excessive Agency | nemo | 100% | lakera | 100% |
| LLM09 | Overreliance | lakera | 100% | llama_firewall | 100% |
| LLM10 | Model Theft | nemo | 20% | lakera | 20% |

---

## Content Moderation Results

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
| nemo | 100% | 100% | 100% | 100% | 100% |
| lakera | 100% | 100% | 100% | 100% | 100% |
| azure_content_safety | 100% | 100% | 100% | 80% | 95% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |
| llama_firewall | 100% | 100% | 100% | 100% | 100% |
| llm_guard | 100% | 100% | 100% | 40% | 85% |
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
| llm_guard | 80.0% | 0 ms | Ultra-fast | Real-time, high-throughput pipelines |
| guardrails_ai | 2.6% | 374 ms | Moderate | Batch processing, async pipelines |
| aws_bedrock | 59.0% | 420 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 25.6% | 570 ms | Moderate | Batch processing, async pipelines |
| lakera | 83.3% | 572 ms | Moderate | Batch processing, async pipelines |
| azure_prompt_shields | 24.4% | 582 ms | Moderate | Batch processing, async pipelines |
| llama_firewall | 85.9% | 1010 ms | Slow | Offline analysis, compliance audits |
| presidio | 6.4% | 1153 ms | Slow | Offline analysis, compliance audits |
| nemo | 83.3% | 29607 ms ⚠️ | Slow (pre-fix measurement — see note above) | Real-time with Bedrock + Semaphore(1) (~3–7 s/probe) |
| openai_moderation | 100.0% | 33648 ms | Slow | Offline analysis, compliance audits |

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
