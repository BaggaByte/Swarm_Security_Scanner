# BENCHMARK REPORT 2026 Q4
## Swarm Security Scanner — Phase 1 CVE Detection Validation

**Version:** 1.0-draft · **Date:** October 2026 · **Status:** IN PROGRESS  
**Target:** Gate 1 — ≥90% recall on 20 real CVEs before Month 4

---

## Executive Summary

This report documents **Phase 1 validation** of the Swarm Security Scanner against a curated corpus of 20 real CVEs sourced from official security advisories. The scanner uses a 5-agent LLM discovery swarm with 2 adversarial challengers, layered on top of Bandit and Semgrep static analysis baselines.

> **Goal:** Prove Swarm detects real security vulnerabilities at recall >90% while suppressing post-patch false positives to <12%.

---

## Benchmark Corpus

| Ecosystem | Repositories | CVEs | Severity Distribution |
|---|---|---|---|
| **Python** | django, flask, pyjwt, requests, starlette, redis-py, pytest | 10 | 2 CRITICAL, 5 HIGH, 3 MEDIUM |
| **JavaScript** | sheetjs, webpack, browserify-sign, nconf, xmldom, vm2 | 6 | 2 CRITICAL, 3 HIGH, 1 MEDIUM |
| **Go** | golang/net, golang/go | 4 | 0 CRITICAL, 4 HIGH, 0 MEDIUM |
| **Total** | 10 projects | **20** | 4 CRITICAL, 12 HIGH, 4 MEDIUM |

### Selection Criteria

Each CVE case satisfies all of:
- **Immutable commit SHAs** — both vulnerable and patched versions are pinned to full 40-character Git SHAs
- **Official advisory** — linked to CVE database, GitHub Security Advisory, or language-ecosystem advisory
- **Exact affected file** — the vulnerable source file is specified for scoped discovery
- **Finding signatures** — CWE identifier or ≥2 specific keyword matches for objective scoring

---

## Methodology

### Paired Snapshot Evaluation

For each CVE, Swarm scans two repository states:

1. **Vulnerable snapshot** — the commit immediately before the security fix
2. **Patched snapshot** — the commit containing the fix (or later stable release)

A CVE is scored as a **True Positive (TP)** if Swarm issues a confirmed finding that:
- Identifies the correct source file
- Contains a CWE match or keyword match from the advisory signature
- Passes challenger consensus (≥1 challenger confirms as TP)

A **Post-Patch False Positive (FP)** is scored when Swarm still flags the CVE location in the patched commit.

### Scoring Formula

| Metric | Formula |
|---|---|
| **Recall** | TP / (TP + FN) |
| **Precision** | TP / (TP + FP) |
| **F1** | 2·TP / (2·TP + FP + FN) |
| **FP Rate** | FP / (FP + TN) |
| **Severity Accuracy** | % of TP findings with correct severity |

### Tools Used

- **SAST Baseline:** Bandit (Python), Semgrep (multi-language) — run concurrently
- **Swarm Discovery:** 5 specialized agents (Architect, SAST Expert, Exploit Expert, Defense Expert, Context Expert)
- **Challenger Phase:** 2 adversarial challengers achieve consensus before confirming findings
- **LLM:** Configurable — local Ollama (llama3.2, qwen2.5-coder:7b) or cloud (NVIDIA NIM Nemotron, Groq)

---

## Results

> ⚠️ **Results pending** — Run the benchmark harness to populate this section.
>
> ```bash
> python cycle11_ollama_swarm/benchmark_cves.py \
>   --manifest benchmarks/cve_manifest.json \
>   --output-dir results/cve_benchmark
> ```

### Summary Table *(to be populated after run)*

| Metric | Swarm | SAST Baseline | Target | Status |
|---|---|---|---|---|
| **Recall** | — | — | ≥90% | ⏳ Pending |
| **Precision** | — | — | ≥85% | ⏳ Pending |
| **F1 Score** | — | — | ≥87% | ⏳ Pending |
| **FP Rate (post-patch)** | — | — | ≤12% | ⏳ Pending |
| **Severity Accuracy** | — | — | ≥80% | ⏳ Pending |
| **Avg Scan Time** | — | — | ≤2 min | ⏳ Pending |

### Per-CVE Results *(to be populated)*

| CVE | Project | Severity | Swarm TP | SAST TP | Sev. Correct | Status |
|---|---|---|---|---|---|---|
| CVE-2023-36053 | django/django | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-34265 | django/django | CRITICAL | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2021-44420 | django/django | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-43665 | django/django | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-30861 | pallets/flask | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-29217 | jpadilla/pyjwt | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-32681 | psf/requests | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-42969 | pytest-dev/pytest | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-35945 | encode/starlette | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-28858 | redis/redis-py | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-30533 | SheetJS/sheetjs | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-37601 | webpack/webpack | CRITICAL | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-46234 | browserify-sign | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-21803 | indexzero/nconf | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-39353 | xmldom/xmldom | CRITICAL | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-29017 | patriksimek/vm2 | CRITICAL | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-44487 | golang/net | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-27664 | golang/net | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2023-39325 | golang/go | HIGH | ⏳ | ⏳ | ⏳ | Pending |
| CVE-2022-41717 | golang/go | MEDIUM | ⏳ | ⏳ | ⏳ | Pending |

---

## Vulnerability Classes Covered

| CWE | Description | Count |
|---|---|---|
| CWE-89 | SQL Injection | 1 |
| CWE-94 | Code Injection / Sandbox Escape | 1 |
| CWE-327 | Weak Cryptographic Algorithm | 1 |
| CWE-330 | Use of Insufficiently Random Values | 1 |
| CWE-347 | Improper Verification of Cryptographic Signature | 1 |
| CWE-384 | Session Fixation | 1 |
| CWE-399 | Resource Management Errors | 1 |
| CWE-400 | Uncontrolled Resource Consumption (DoS) | 7 |
| CWE-601 | URL Redirection to Untrusted Site | 2 |
| CWE-1321 | Prototype Pollution | 4 |
| CWE-1333 | Regex Denial of Service (ReDoS) | 2 |

---

## Competitive Context

### Why This Benchmark Matters

Traditional SAST tools (Bandit, Semgrep, Snyk Code) report **raw findings** without reasoning. Swarm adds:

1. **Consensus filtering** — 5 agents must independently identify the vulnerability before the challenger phase
2. **Adversarial challenge** — challengers argue against findings, reducing FPs
3. **Evidence chain** — each confirmed finding includes hypothesis, attack path, and rationale

Published academic benchmarks (e.g., [Vulnhuntr 2024](https://github.com/protectai/vulnhuntr)) show pure LLM scanners achieving 65-75% recall on Python CVEs with high FP rates. Swarm's hybrid SAST+LLM architecture is designed to exceed this by anchoring discovery to static analysis findings while expanding coverage via novel flaw discovery.

### Phase 1 Gate Criteria

| Gate | Condition | Required |
|---|---|---|
| ✅ PROCEED to Phase 2 | Recall ≥90% on ≥18/20 CVEs | Run benchmark |
| ⚠️ PARTIAL | Recall 85-89% | Tune discovery prompt + re-run |
| ❌ PIVOT | Recall <85% | Reposition as "FP elimination tool" |

---

## Scan Configuration

```bash
# Full benchmark (recommended for public reporting)
python cycle11_ollama_swarm/benchmark_cves.py \
  --manifest benchmarks/cve_manifest.json \
  --output-dir results/cve_benchmark \
  --model qwen2.5-coder:7b \
  --challenger-model llama3.2 \
  --workers 3 \
  --challengers 2

# Quick smoke test (3 chunks per CVE)
python cycle11_ollama_swarm/benchmark_cves.py \
  --manifest benchmarks/cve_manifest.json \
  --output-dir results/cve_benchmark_quick \
  --max-chunks 3

# With NVIDIA NIM (fastest, requires NVIDIA_API_KEY)
python cycle11_ollama_swarm/benchmark_cves.py \
  --manifest benchmarks/cve_manifest.json \
  --output-dir results/cve_benchmark_nim \
  --model nvidia/llama-3.1-nemotron-70b-instruct \
  --challenger-model nvidia/nemotron-3.5-lightning-30b-a3b
```

---

## Next Steps

### Week 2–4 (Phase 1 completion)
- [ ] Run full 20-CVE benchmark
- [ ] Populate results tables above
- [ ] Identify missed CVEs and tune discovery prompts
- [ ] Measure average wall-clock scan time (target: <2 min with `--max-chunks`)
- [ ] Publish results to GitHub + Medium article

### Month 2–4 (Phase 1 polish)
- [ ] Expand corpus to 40 CVEs (add Rails/Spring/Kubernetes)
- [ ] Benchmark against Semgrep Pro and Snyk Code API
- [ ] Achieve documented ≥92% recall for Gate 1
- [ ] Export SARIF-formatted findings for IDE integration

---

## Reproducibility

All benchmark inputs are committed to this repository:
- **Manifest:** [`benchmarks/cve_manifest.json`](benchmarks/cve_manifest.json) — 20 CVEs with immutable SHAs
- **Schema:** [`benchmarks/cve_manifest.schema.json`](benchmarks/cve_manifest.schema.json) — JSON schema for manifest validation
- **Harness:** [`cycle11_ollama_swarm/benchmark_cves.py`](cycle11_ollama_swarm/benchmark_cves.py) — paired scan runner
- **Live report:** `results/cve_benchmark/cve_benchmark_report.json` — generated incrementally by the harness

To reproduce: clone the repo, install dependencies, configure your LLM provider in `.env`, and run the benchmark command above.

---

*Swarm Security Scanner · Phase 1 VALIDATE · October 2026*  
*Status: IN PROGRESS — Gate 1 target: ≥90% recall by Month 4*
