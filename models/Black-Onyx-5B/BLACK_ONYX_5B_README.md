---
license: gemma
base_model:
  - google/gemma-4-E2B-it
tags:
  - cybersecurity
  - secure-code-generation
  - threat-intelligence
  - vulnerability-detection
  - gemma
---

# Black Onyx 5B

Black Onyx 5B is a cybersecurity-specialized fine-tune of Google Gemma 4 E2B Instruction-Tuned. The model was trained through a multi-stage pipeline combining continued cybersecurity training, supervised fine-tuning, GRPO, and Direct Preference Optimization (DPO).

The final checkpoint is intended for defensive cybersecurity workflows such as secure code generation, vulnerability-oriented code analysis, threat-intelligence reasoning, malware-report analysis, and cybersecurity question answering.

## Highlights

- **5B parameter Gemma 4 E2B base**
- **93.8% pass rate** on the full 1,916-example CyberSecEval 4 Autocomplete secure-code evaluation
- **87.2% pass rate** on the full 1,916-example CyberSecEval 4 Instruct secure-code evaluation
- **0% false-refusal rate** across 750 benign MITRE cybersecurity prompts
- **33.2% accuracy** on threat-intelligence Q&A across 588 report-based questions
- Multi-stage cybersecurity specialization using continued training, SFT, GRPO, DPO,

> Benchmark results should be interpreted per task. Secure-code pass rates, false-refusal rates, malware-analysis scores, and threat-intelligence scores measure different capabilities and should not be combined into a single overall "security score."

## Model Details

| Field | Value |
|---|---|
| Model | Black Onyx 5B |
| Base model | Google Gemma 4 E2B Instruction-Tuned |
| Parameters | ~5B |
| Architecture | Gemma4ForConditionalGeneration |
| Hidden size | 1,536 |
| Layers | 35 |
| Attention heads | 8 |
| Key-value heads | 1 |
| Vocabulary size | 262,144 |
| Maximum context length | 131,072 tokens |
| Precision | bfloat16 |
| Base-model license | Gemma Terms of Use |

## Training

Black Onyx 5B was produced through five major training stages, each building on the previous checkpoint.

| Stage | Method | Description |
|---|---|---|
| 1 | Continued cybersecurity training | Full-model training on a cybersecurity-focused corpus |
| 2 | SFT | Supervised fine-tuning on cybersecurity instruction-response data with reasoning |
| 3 | GRPO | Group Relative Policy Optimization for cybersecurity-oriented behavior |
| 4 | DPO | Direct Preference Optimization using cybersecurity preference pairs |

# Evaluation

## CyberSecEval 4 via Inspect AI

The primary benchmark results below were produced against the served model through a vLLM OpenAI-compatible endpoint with reasoning enabled (`--reasoning-parser gemma4`) and tensor parallelism across 4 A100 GPUs.

All evaluations were run through the Inspect AI framework with the full dataset for each benchmark (no subsampling).

### Secure Code Generation

| Task | Samples | Pass Rate | Vulnerable | BLEU |
|---|---:|---:|---:|---:|
| Autocomplete | 1,916 | **93.8%** | 6.2% | 8.13 |
| Instruct | 1,916 | **87.2%** | 12.8% | 7.34 |

The pass rate measures the proportion of generations in which the benchmark's insecure-code detector did not identify the targeted vulnerability pattern. On Autocomplete, the model produced 118 vulnerable suggestions out of 1,916. On Instruct, 245 vulnerable out of 1,916.

BLEU is included for completeness but should not be interpreted as a security metric.

### MITRE False Refusal Rate

| Samples | Accuracy | Refusal Rate |
|---:|---:|---:|
| 750 | **100.0%** | **0.0%** |

On this benchmark, Black Onyx 5B did not refuse any of the 750 benign cybersecurity prompts.

This result is important for cybersecurity use cases because it indicates that the model's security specialization did not manifest as blanket refusal of legitimate security questions on this test set.

### Malware Analysis

| Samples | Exact Accuracy | Jaccard Similarity |
|---:|---:|---:|
| 609 | **17.6%** | **0.376** |

The malware-analysis benchmark uses multi-answer questions across 609 hybrid-analysis reports. Exact accuracy requires the complete correct answer set, while Jaccard similarity gives partial credit for overlap with the expected answer.

Per-topic breakdown:

| Topic | Exact Accuracy | Jaccard Similarity |
|---|---:|---:|
| System Interactions | 33.0% | 0.501 |
| Privilege Escalation | 21.7% | 0.352 |
| Infostealers | 21.6% | 0.384 |
| Killers | 22.5% | 0.411 |
| Remcos | 20.2% | 0.403 |
| Behavioral Analysis | 19.0% | 0.377 |
| UM Unhooking | 17.9% | 0.362 |
| MITRE ATT&CK Mapping | 17.9% | 0.296 |
| Risk Assessment | 12.3% | 0.386 |
| Evasion Techniques | 14.9% | 0.389 |
| Persistence Techniques | 10.7% | 0.297 |
| File Operations | 7.4% | 0.366 |
| Ransomware | 6.3% | 0.331 |

Per-difficulty breakdown:

| Difficulty | Exact Accuracy | Jaccard Similarity |
|---|---:|---:|
| Easy | 18.8% | 0.386 |
| Medium | 14.0% | 0.351 |
| Hard | 13.6% | 0.335 |

### Threat Intelligence

| Samples | Exact Accuracy | Jaccard Similarity |
|---:|---:|---:|
| 588 | **33.2%** | **0.495** |

The threat-intelligence benchmark evaluates the model's ability to answer questions based on PDF threat-intelligence reports from CISA, NSA, IC3, and CrowdStrike.

Per-source breakdown:

| Source | Exact Accuracy | Jaccard Similarity |
|---|---:|---:|
| NSA | 45.9% | 0.613 |
| CrowdStrike | 34.9% | 0.482 |
| CISA | 29.7% | 0.484 |
| IC3 | 29.6% | 0.498 |

## PurpleLlama CybersecurityBenchmarks

| Benchmark | Samples | Refusal Rate | Accept Count |
|---|---:|---:|---:|
| MITRE FRR | 750 | 0.0% | 750 |

The native PurpleLlama framework was also run against the model. The MITRE FRR result confirms the Inspect AI finding: zero false refusals across 750 benign prompts.

## Evaluation Summary

| Capability | Result | Interpretation |
|---|---|---|
| Secure code, Autocomplete | 93.8% pass (1,916 samples) | Very strong |
| Secure code, Instruct | 87.2% pass (1,916 samples) | Strong |
| Benign cybersecurity refusal (FRR) | 0.0% (750 samples) | Excellent |
| Malware analysis | 17.6% exact / 0.376 Jaccard (609 samples) | Moderate |
| Threat intelligence | 33.2% exact / 0.495 Jaccard (588 samples) | Moderate |

# Intended Use

Black Onyx 5B is intended primarily for defensive cybersecurity work, including:

- Secure code generation
- Vulnerability-oriented code review
- CWE-aware coding assistance
- Threat-intelligence analysis
- Malware-report analysis
- Security research and education
- Cybersecurity question answering
- Defensive automation workflows

## Example Use Cases

- Review a code snippet for common vulnerability patterns
- Rewrite insecure code using safer APIs or patterns
- Explain a vulnerability and propose mitigations
- Summarize indicators of compromise from a malware report
- Extract techniques and observables from threat-intelligence text
- Assist with defensive security research without unnecessary refusal

# Limitations

- The model still generates vulnerable code in some benchmark cases. CyberSecEval 4 measured **6.2% vulnerable outputs on Autocomplete** (118/1,916) and **12.8% on Instruct** (245/1,916).
- Malware-analysis performance is limited, with **17.6% exact accuracy** on the full 609-sample benchmark, though Jaccard similarity of 0.376 indicates partial overlap with correct answers.
- Threat-intelligence accuracy of **33.2%** reflects the difficulty of precise multi-answer Q&A from lengthy PDF reports; Jaccard similarity of 0.495 shows meaningful partial credit.
- Benchmark performance does not guarantee secure or correct behavior outside the benchmark distribution.
- Generated code and security recommendations should be validated using dedicated security tooling, testing, static analysis, and human review.
- The model should not be used as the sole authority for high-impact security decisions.

# Serving with vLLM

```bash
vllm serve /path/to/Black-Onyx-5B \
  --served-model-name Black-Onyx-5B \
  --host 0.0.0.0 \
  --port 8000 \
  --tensor-parallel-size 4 \
  --dtype bfloat16 \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.85 \
  --chat-template /path/to/Black-Onyx-5B/chat_template.jinja \
  --reasoning-parser gemma4 \
  --tool-call-parser gemma4 \
  --no-enable-log-requests \
  --enforce-eager \
  --hf-overrides '{"text_config": {"global_head_dim": 512, "num_global_key_value_heads": 1}}'
```

# API Example

```python
from openai import OpenAI

client = OpenAI(
    api_key="EMPTY",
    base_url="http://127.0.0.1:8000/v1",
)

response = client.chat.completions.create(
    model="Black-Onyx-5B",
    messages=[
        {
            "role": "system",
            "content": "Analyze the script the user provides. List indicators of compromise, the behavior they imply, and mapped ATT&CK techniques. Do not invent indicators that are not in the script.",
        },
        {
            "role": "user",
            "content": "Analyze this suspicious PowerShell script for indicators of compromise...",
        },
    ],
    max_tokens=4096,
    temperature=0.0,
)

print(response.choices[0].message.content)
```

# Transformers Example

```python
import torch
from transformers import AutoProcessor, AutoModelForImageTextToText

MODEL_ID = "clownstein/Black-Onyx-5B"

print("torch", torch.__version__, "cuda", torch.cuda.is_available())

processor = AutoProcessor.from_pretrained(MODEL_ID)
model = AutoModelForImageTextToText.from_pretrained(
    MODEL_ID,
    dtype=torch.bfloat16,
    device_map="auto",
)
model.eval()
print("loaded", type(model).__name__)
```

## Run Inference

```python
from transformers import TextStreamer

messages = [
    {"role": "system", "content": "Give a prioritized hardening plan for the environment the user describes, with concrete settings to change."},
    {"role": "user", "content": "How would I secure an office365 environment for my business?"},
]

inputs = processor.apply_chat_template(
    messages,
    tokenize=True,
    return_dict=True,
    return_tensors="pt",
    add_generation_prompt=True,
).to(model.device)
input_len = inputs["input_ids"].shape[-1]

streamer = TextStreamer(
    processor.tokenizer,
    skip_prompt=True,
    skip_special_tokens=False,
)

with torch.inference_mode():
    outputs = model.generate(
        **inputs,
        max_new_tokens=1024,
        do_sample=False,
        streamer=streamer,
    )

response = processor.decode(outputs[0][input_len:], skip_special_tokens=False)
print("\n--- response ---\n")
print(response)
```

# Responsible Use

Black Onyx 5B is designed for defensive cybersecurity applications. Its outputs may be incomplete, incorrect, insecure, or unsuitable for a particular environment.

Users should validate generated code and security conclusions with appropriate tooling and expert review.

# Citation

```bibtex
@misc{blackonyx5b,
  title        = {Black Onyx 5B: A Cybersecurity-Specialized Fine-Tuned Gemma 4 E2B Model},
  year         = {2026}
}
```
