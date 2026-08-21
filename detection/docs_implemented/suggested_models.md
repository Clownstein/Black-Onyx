# Suggested Models: Filling Platform Gaps

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


**Document version:** 1.0  
**Date:** July 26, 2026  
**Context:** Follow-up to the Antares-1B review. Antares fits agentic CWE/CVE file localization and CI-driven repo triage, but does **not** fill the core streaming needs of AutoAnalyzer. This document surveys models and techniques that address those gaps.

**Gaps addressed (from Antares “Your need” column):**

| Gap | Why Antares fails here | What we need instead |
|---|---|---|
| G1. Continuous streaming detection (logs / flows / metrics) | Wrong problem (terminal agent, not Kafka scorers) | Compact sequence / multivariate anomaly models |
| G2. Code change risk on diffs | Different I/O; multi-turn shell loop | Diff/function classifiers with risk scores |
| G3. Explainable findings + calibrated scores | File list only; File F1 ~0.21; no exploit explanation | Contributor attributions + score calibration |
| G4. Commodity CPU / ONNX | Decoder LLM; H100-class eval setup | Encoder / sklearn / small transformer + ONNX Runtime |

**Out of scope for this file:** Implementing models, editing `planned_upgrades.md`, or adopting Antares into the hot path.

---

## How this maps to AutoAnalyzer today

| Modality | Current approach | Gap coverage |
|---|---|---|
| Logs | Compact BERT-style encoder + Drain3 + ONNX (`models/log-model`) | G1 partially covered; strengthen with LogBERT-style training + calibration |
| Network | Compact Flow Transformer (h=128, L=3) + ONNX (`models/network-model`) | G1 partially covered; evaluate FlowTransformer / UniNet ideas |
| Metrics | Multivariate Metric Transformer + Isolation Forest fallback + ONNX (`models/metrics-model`) | G1 partially covered; TranAD / Anomaly Transformer for stronger diagnosis |
| Code | Hybrid local features + sklearn LogisticRegression (`models/code-model`) | **G2 largest gap** vs DistilBERT / CodeBERT / CodeReviewer |
| All | `raw_score` / `calibrated_score` / `contributors` in findings | **G3** needs systematic Platt/isotonic + attribution |
| Serving | ONNX Runtime + joblib | **G4** already the design target; keep models in this envelope |

---

## G1 — Continuous streaming detection

### Logs

| Candidate | Type | Fit | Notes |
|---|---|---|---|
| **LogBERT** | Self-supervised BERT on log-key sequences | **Strong** | Masked log-key prediction + hypersphere minimization; works with Drain/Drain3 templates — matches your existing parser path. Paper: [arXiv:2103.04475](https://arxiv.org/abs/2103.04475). Keep 2-layer compact encoder (paper uses dim 50/256). |
| **DeepLog** | LSTM next-log-key prediction | Moderate | Classic baseline; weaker than transformers on long context but tiny and easy to ONNX-export. Good fallback / A/B control. |
| **DistilBERT / custom Distil log LM** | Small transformer on templates or perplexity | Strong for CPU | Unsupervised “normal language of logs” + perplexity spike (e.g. Server-Savior-AI pattern). Train on *your* tenants’ normal data. |
| **LogTinyLLM (LoRA on ~1.5B)** | PEFT tiny LLM | Weak for hot path | Strong reported accuracy on Thunderbird, but still LLM-class latency/memory — use only for offline investigation, not Kafka scoring. [arXiv:2507.11071](https://arxiv.org/pdf/2507.11071) |
| **Hybrid BERT + XGBoost** (community packs) | Embedding → tree scorer | Moderate | Fast inference; less principled for sequence anomalies; useful as a cheap ensemble member. |

**Recommendation for logs:** Stay on a **LogBERT-style compact encoder** (aligns with current `log-model`). Improve with tenant-specific self-supervised pretrain on Drain3 keys, then export ONNX. Do **not** replace with Antares or LogTinyLLM on the streaming path.

### Network flows

| Candidate | Type | Fit | Notes |
|---|---|---|---|
| **FlowTransformer** | Modular transformer NIDS framework for NetFlow/IPFIX | **Strong** | Swap encoding / transformer / classification head; designed for flow sequences. Paper: [arXiv:2304.14746](https://arxiv.org/abs/2304.14746). Your `network-model` is already in this family. |
| **UniNet (T-Attent)** | Lightweight hierarchical transformer (session/flow/packet) | Strong | Attention heatmaps for interpretability; unsupervised anomaly head (masked feature prediction). [GitHub Binghui99/UniNet](https://github.com/Binghui99/UniNet) |
| **Deterministic detectors** (you already have) | Port scan / beacon heuristics | Required | Keep as first-stage or parallel findings; transformers should *complement*, not replace. |

**Recommendation for network:** Keep compact Flow Transformer; borrow **UniNet-style multi-granularity features** and attention contribution maps for `contributors[]`. Evaluate FlowTransformer head choices on your Zeek/NetFlow features before growing model size.

### Metrics

| Candidate | Type | Fit | Notes |
|---|---|---|---|
| **TranAD** | Small adversarial transformer for MTS | **Strong** | Fast train/inference; per-feature diagnosis; production reports of **&lt;20 ms CPU**, ~127k params. Paper: [arXiv:2201.07284](https://arxiv.org/abs/2201.07284); deployment write-up: [Striim TranAD](https://www.striim.com/blog/tranad-multivariate-anomaly-detection/). |
| **Anomaly Transformer** | Association-discrepancy attention | Strong accuracy | SOTA-ish on SMD/SMAP/MSL; more compute-hungry. Good when GPU available or windows are small. [ICLR 2022](https://openreview.net/forum?id=LzQQ89U1qm_) |
| **MEMTO** | Memory-guided transformer | Strong accuracy | Improves on Anomaly Transformer F1; heavier. Research upgrade path. |
| **OmniAnomaly** | GRU + VAE reconstruction probability | Moderate | Strong diagnosis via reconstruction; slower than TranAD. |
| **Isolation Forest** | Classical multivariate outlier | **Strong for CPU fallback** | You already ship this; keep as ONNX/joblib safety net when transformer fails or cold-starts. |

**Recommendation for metrics:** Prefer **TranAD** (or your current compact transformer) as primary; keep **Isolation Forest** fallback. Consider Anomaly Transformer only if diagnosis quality justifies cost.

---

## G2 — Code change risk on diffs

Antares localizes files from a CWE description via shell exploration. AutoAnalyzer’s Model B needs **risk score on a specific diff/change** in the Kafka path.

| Candidate | Type | Fit | Notes |
|---|---|---|---|
| **microsoft/CodeBERT** (`codebert-base`) | Encoder for NL+PL | Strong | Fine-tune as binary / multi-label vuln or risk classifier on functions/diffs; proven ONNX export (community: ~sub-250 ms FastAPI). [GitHub microsoft/CodeBERT](https://github.com/microsoft/CodeBERT) |
| **DistilBERT (code-tuned)** | Distilled encoder | **Best CPU tradeoff** | Recent vuln-detection work shows DistilBERT can match/near larger models with far less train/infer cost when data is balanced. [arXiv:2604.00112](https://arxiv.org/pdf/2604.00112) |
| **DB-CBIL (DistilBERT + CNN + BiLSTM)** | Hybrid detector | Moderate | Higher recall / lower FNR on SARD; more pipeline complexity. |
| **microsoft/codereviewer** | Pretrained on diffs + reviews | **Strong for PR/diff risk** | Quality estimation (`cls`) takes old file + diff hunk → “needs comment / risky change”. Closest pretrained task to your Model B. Comment generation optional for evidence text. [HF microsoft/codereviewer](https://huggingface.co/microsoft/codereviewer) |
| **GraphCodeBERT** | Code + data-flow | Strong for semantic vulns | Better for data-flow sensitive issues than bag-of-tokens; heavier than DistilBERT. |
| **UniXcoder** | Unified encode/decode | Moderate | Flexible embeddings for similarity / risk features; can feed sklearn head (keeps your hybrid design). |
| **Antares-1B** | Agentic localizer | **Offline only** | Use for advisory→files triage / CI sweeps, not streaming diff scoring. |

**Recommendation for code:**

1. **Hot path (replace/upgrade `code-model`):** DistilBERT or CodeBERT encoder → risk head, **or** fine-tune CodeReviewer quality-estimation on your labeled diffs; export ONNX. Keep Semgrep/heuristics as deterministic contributors.
2. **Warm/async path:** Antares (or similar) for CWE/CVE → candidate files when an incident already exists.
3. Prefer **data quality + balanced labels** over jumping to 1B+ LLMs for the scoring path.

---

## G3 — Explainable findings and calibrated scores

This is less a single “model” and more a **scoring stack** every modality should share.

### Explainability (contributor evidence)

| Technique | Best with | How it helps AutoAnalyzer |
|---|---|---|
| **Attention / association maps** | LogBERT, FlowTransformer, UniNet, Anomaly Transformer | Map high-attention templates, flows, or timesteps → `contributors[]` |
| **Reconstruction residual per feature** | TranAD, OmniAnomaly, autoencoders | Per-metric / per-channel “blame” for metrics findings |
| **Masked prediction mismatch** | LogBERT (masked keys not in top-g) | Unexpected template at position N |
| **SHAP / TreeExplainer** | Isolation Forest, XGBoost, sklearn heads | Feature attributions for tabular / hybrid code features |
| **Deterministic rule tags** | Semgrep, flow detectors | Always attach rule ID / CWE as contributor |

**Practical rule:** Compute SHAP/attention on the **raw model score**, then map to calibrated probability separately (SHAP on post-isotonic outputs breaks additivity).

### Calibration (trustworthy `calibrated_score`)

| Method | When to use | Source |
|---|---|---|
| **Platt scaling (sigmoid)** | Small validation sets; preserve ranking | [sklearn calibration](https://scikit-learn.org/stable/modules/calibration.html) |
| **Isotonic regression** | Larger holdout; non-sigmoid distortion | Same |
| **Temperature scaling** | Multi-class heads | Same |
| **POT / peak-over-threshold** | Unsupervised reconstruction scores (OmniAnomaly-style) | OmniAnomaly / TranAD ecosystems |
| **Conformal prediction (optional)** | Need prediction sets / uncertainty for analysts | Research upgrade |

**Recommendation:** Add a shared `packages/black_onyx_calibration/` (or equivalent) used by all four model services: fit calibrators per tenant/service on analyst feedback + synthetic holds; persist alongside ONNX artifacts; emit both `raw_score` and `calibrated_score` (you already have schema fields — make them real).

---

## G4 — Commodity CPU / ONNX serving

| Candidate / practice | Role | Notes |
|---|---|---|
| **ONNX Runtime** | Primary inference | Already your target; keep exporting transformers via `torch.onnx` / Hugging Face Optimum. |
| **DistilBERT / MiniLM** | Small text/code encoders | `sentence-transformers/all-MiniLM-L6-v2` (+ ONNX variants) for embedding features; DistilBERT for classification heads. |
| **Isolation Forest (joblib / sklearn-onnx)** | Metrics / tabular fallback | Proven CPU path; you already use joblib. |
| **Quantization (int8)** | Shrink CodeBERT-class models | Memory ↓; validate F1 drop (~single-digit % MCC in CodeBERT compression studies). [arXiv:2412.13737](https://arxiv.org/pdf/2412.13737) |
| **TranAD-scale transformers** | Metrics | ~1e5 params → comfortable CPU at Kafka rates. |
| **Avoid on hot path** | Antares-1B, frontier LLMs, LogTinyLLM full decode | GPU / multi-second multi-turn loops |

**Hard envelope for streaming models (suggested):**

- Prefer **encoder-only** or classical ML (not decoder agents).
- Target **p95 &lt; 50–100 ms** per feature window on CPU for logs/network/metrics; code can be slightly higher if async.
- Ship **ONNX primary + classical fallback** for metrics (already your pattern).
- Gate any &gt;350M decoder models behind **async / analyst-triggered** jobs only.

---

## Recommended shortlist (actionable)

### Priority 0 — Closest upgrades to existing services

| Gap | Adopt / evaluate | Modality |
|---|---|---|
| G1 logs | LogBERT-style self-supervised training on Drain3 keys → ONNX | `log-model` |
| G1 metrics | TranAD (or keep current transformer) + Isolation Forest | `metrics-model` |
| G1 network | Stay FlowTransformer-class; add UniNet-style attributions | `network-model` |
| G2 code | DistilBERT or CodeReviewer quality-estimation fine-tune → ONNX | `code-model` |
| G3 | Platt/isotonic calibrators + attention/residual contributors | all |
| G4 | Optimum/onnxruntime + int8 for code encoder if needed | all |

### Priority 1 — Research / secondary detectors

| Gap | Candidate | Role |
|---|---|---|
| G1 metrics | Anomaly Transformer / MEMTO | Higher-accuracy offline or GPU path |
| G1 network | UniNet unsupervised head | Alternate network scorer |
| G2 code | GraphCodeBERT | Semantic / data-flow vulns |
| G2 code | CodeBERT on BigVul-style labels | Function-level vuln score |
| G3 | Conformal prediction | Uncertainty bands for analysts |

### Priority 2 — Explicitly offline / non-streaming

| Need Antares already covers | Model | Role |
|---|---|---|
| Agentic CWE → files | **Antares-1B** (or 350M if tighter) | Sandboxed CI / incident enrichment |
| Advisory-driven triage | Antares CLI (SARIF/JSON) | Analyst-triggered |

---

## Decision matrix vs Antares

| Need | Prefer | Avoid for this need |
|---|---|---|
| Stream log anomalies | LogBERT / Distil log encoder | Antares |
| Stream flow anomalies | FlowTransformer / UniNet | Antares |
| Stream metrics anomalies | TranAD / Anomaly Transformer / Isolation Forest | Antares |
| Score a PR/diff risk | CodeReviewer / DistilBERT / CodeBERT | Antares (wrong loop) |
| Explain + calibrate | Attention residuals + Platt/isotonic | Antares file list alone |
| CPU ONNX hot path | Encoders ≤ DistilBERT/CodeBERT + classical ML | Antares-1B |
| Find files for a CWE in a repo | Antares | Streaming encoders |

---

## Suggested evaluation protocol

For each shortlist candidate:

1. **Contract fit** — Must emit `raw_score`, `calibrated_score`, `contributors[]` compatible with `contracts/` and `inference-worker`.
2. **Latency** — Measure p50/p95 on CPU with production window sizes.
3. **ONNX export** — Must run under ONNX Runtime (or documented joblib fallback).
4. **Precision on synthetic + golden scenarios** — Use existing `tests/synthetic-anomalies/` and `tests/integration/test_golden_scenario.py` patterns.
5. **Calibration quality** — Expected Calibration Error (ECE) / Brier score on holdout with analyst labels when available.
6. **Shadow deploy** — Canary via `model-gateway` before cutting over.

---

## Key references

- LogBERT: [arXiv:2103.04475](https://arxiv.org/abs/2103.04475)
- LogTinyLLM: [arXiv:2507.11071](https://arxiv.org/pdf/2507.11071)
- FlowTransformer: [arXiv:2304.14746](https://arxiv.org/abs/2304.14746)
- UniNet: [github.com/Binghui99/UniNet](https://github.com/Binghui99/UniNet)
- TranAD: [arXiv:2201.07284](https://arxiv.org/abs/2201.07284) · [Striim production notes](https://www.striim.com/blog/tranad-multivariate-anomaly-detection/)
- Anomaly Transformer: [ICLR 2022](https://openreview.net/forum?id=LzQQ89U1qm_)
- OmniAnomaly: [github.com/NetManAIOps/OmniAnomaly](https://github.com/NetManAIOps/OmniAnomaly)
- CodeBERT / CodeReviewer / GraphCodeBERT / UniXcoder: [github.com/microsoft/CodeBERT](https://github.com/microsoft/CodeBERT)
- Efficient DistilBERT vuln detection: [arXiv:2604.00112](https://arxiv.org/pdf/2604.00112)
- CodeBERT compression / ONNX: [arXiv:2412.13737](https://arxiv.org/pdf/2412.13737)
- sklearn probability calibration: [scikit-learn docs](https://scikit-learn.org/stable/modules/calibration.html)
- Antares-1B (offline triage only): `models/antares-1b/README.md`

---

## Bottom line

Fill Antares’s gaps with **specialist streaming models you already designed for**, upgraded where evidence is strongest:

- **Logs:** LogBERT-class compact encoder  
- **Network:** FlowTransformer-class + better attributions  
- **Metrics:** TranAD-class transformer + Isolation Forest  
- **Code diffs:** DistilBERT / CodeReviewer / CodeBERT — **not** Antares  
- **Explain + calibrate:** shared calibration + attention/residual contributors  
- **CPU/ONNX:** keep the envelope; park Antares (and other agentic LLMs) on async investigation only  

That split keeps AutoAnalyzer’s architecture coherent: **fast modality scorers on the wire**, **heavy agents for human/CI hunts**.
