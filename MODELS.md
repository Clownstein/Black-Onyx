# Models

Black Onyx uses multiple models, each serving a distinct purpose. This document
describes every model, its format, its serving backend, and its role in the
platform.

## Inventory

| Model | Format | Size | Backend | Port | Role |
| --- | --- | --- | --- | --- | --- |
| **Black-Onyx-5B** | GGUF (Q8_0) | 4.9 GB | llama.cpp (`llama-server`) | 8081 (internal) | Main cybersecurity LLM: agent loop, chat completions, security analysis |
| **Black-Onyx-5B mmproj** | GGUF | 987 MB | llama.cpp (mounted with main model) | 8081 | Multimodal projector: vision/image input for the 5B model |
| **Antares-1B** | safetensors | 3.5 GB | vLLM (`vllm-antares`) | 8000 (internal) | Vulnerability localization: CWE → candidate file identification |
| **FunctionGemma 270M** | GGUF (Q8_0) | 278 MB | llama.cpp (`tool-router`, optional) | 8080 (internal) | First-stage tool router: proposes tool calls before the main LLM runs |
| **Log model** | ONNX |   | `log-model` service | 8090 | Log template-sequence Transformer anomaly scorer |
| **Network model** | ONNX |   | `network-model` service | 8101 | Flow Transformer anomaly scorer |
| **Metrics model** | ONNX |   | `metrics-model` service | 8102 | Metric Transformer + IsolationForest anomaly scorer |
| **Code model** | sklearn |   | `code-model` service | 8103 | Hybrid sklearn change-risk scorer |
| **Host-state model** | calibrated |   | `host-state-model` service | 8104 | Pass-through calibrated host-state scorer |
| **Malware-static** | ONNX |   | In-process (`malware-triage`) |   | EMBER-style PE static analysis library |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser (React UI)                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ session cookie + CSRF
┌──────────────────────────────▼──────────────────────────────────────┐
│                          BFF (FastAPI :8100)                         │
│  /api/v1/security/agent/run   → signed short-lived actor assertion   │
│  /api/v1/security/chat        → signed short-lived actor assertion   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Bearer HMAC assertion (SECURITY_GATEWAY_KEY)
┌──────────────────────────────▼──────────────────────────────────────┐
│                  Security Gateway (FastAPI :8000)                    │
│  Agent loop (control-token format)                                   │
│  Tool dispatch → security-runner                                     │
└──────┬───────────────┬──────────────────────────────────────────────┘
       │               │
       │ LLM calls     │ optional tool routing
       │               │
┌──────▼──────┐  ┌─────▼──────────────────────┐
│ llama-server │  │ tool-router (optional)      │
│  :8081       │  │  :8080                      │
│ Black-Onyx-5B│  │ FunctionGemma 270M          │
│ Q8_0 GGUF    │  │ Q8_0 GGUF                   │
│ + mmproj     │  │ (first-stage tool proposal)  │
└──────────────┘  └─────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│              Detection Plane (separate from security tools)           │
├─────────────────────────────────────────────────────────────────────┤
│  code-processor → code-model (:8103) → high-risk findings            │
│       ↓                                                               │
│  code-enrichment-worker (:8110)                                       │
│    ANTARES_ENDPOINT=http://vllm-antares:8000/v1                      │
│       ↓                                                               │
│  ┌─────────────────────┐                                              │
│  │ vllm-antares :8000  │  Antares-1B (safetensors)                    │
│  │ CWE → file locality │  vulnerability localization                 │
│  └─────────────────────┘                                              │
│       ↓                                                               │
│  incident-api (evidence enrichment, human review required)            │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│           Streaming Modality Scorers (Kafka hot path)                │
├─────────────────────────────────────────────────────────────────────┤
│  log-model (:8090)    │ network-model (:8101) │ metrics-model (:8102)│
│  ONNX Transformer     │ ONNX Transformer     │ ONNX + IsolationForest│
│  host-state-model (:8104) │ code-model (:8103) │ malware-static      │
│  pass-through scorer  │ sklearn change-risk  │ EMBER PE (in-process)│
└─────────────────────────────────────────────────────────────────────┘
```

## Model Roles in Detail

### Black-Onyx-5B (Main LLM)

- **What:** 5B-parameter cybersecurity fine-tune of Google Gemma 4 E2B
  Instruction-Tuned. Trained through continued cybersecurity training, SFT,
  GRPO, and DPO.
- **Format:** GGUF (Q8_0 quantization, 4.9 GB)
- **Served by:** `llama-server` container using `ghcr.io/ggml-org/llama.cpp:server-cuda`
- **Endpoint:** `http://llama-server:8081` (OpenAI-compatible)
- **Used by:** Security gateway agent loop (`/v1/agent/run`), chat completions
  (`/v1/chat/completions`), and the main BFF LLM provider (`config.yaml`).
- **Strengths:** Secure code generation, vulnerability-oriented code analysis,
  threat-intelligence reasoning, malware-report analysis, cybersecurity Q&A.
  93.8% pass rate on CyberSecEval 4 Autocomplete, 0% false-refusal rate.

### Black-Onyx-5B mmproj (Vision Projector)

- **What:** Multimodal projector enabling image input for the Black-Onyx-5B model.
- **Format:** GGUF (987 MB)
- **Served by:** Same `llama-server` container, mounted via `--mmproj`.
- **Use case:** Screenshot analysis, diagram interpretation, visual threat
  intelligence. The model can accept images alongside text prompts.

### Antares-1B (Vulnerability Localization)

- **What:** Cisco Foundation AI Antares-1B on IBM Granite 4.0 1B backbone.
  Two-stage training: SFT then GRPO for terminal-agent vulnerability
  localization (CWE → candidate files).
- **Format:** safetensors (3.5 GB), **not** GGUF, so vLLM is required (not
  llama.cpp).
- **Served by:** `vllm-antares` container using `vllm/vllm-openai:v0.10.2`
- **Endpoint:** `http://vllm-antares:8000` (OpenAI-compatible completions)
- **Used by:** `code-enrichment-worker` (port 8110) via `ANTARES_ENDPOINT`.
  The worker runs the Antares CLI `tool query` and `tool sweep` commands to
  localize vulnerable files from CWE identifiers.
- **Strengths:** File-level vulnerability localization via allowlisted shell
  inspection. Produces advisory leads for human review, not proof of
  vulnerability.
- **Important:** This is a completions endpoint, not chat completions. The
  Antares CLI expects `POST /v1/completions`; chat completions templates
  break tool prompts.

### FunctionGemma 270M (Tool Router, Optional)

- **What:** Small 270M-parameter model fine-tuned for function/tool calling.
- **Format:** GGUF (Q8_0, 278 MB)
- **Served by:** `tool-router` container using `ghcr.io/ggml-org/llama.cpp:server-cuda`
  (started with `--profile tool-router`)
- **Endpoint:** `http://tool-router:8080` (OpenAI-compatible with native
  tool-calling support)
- **Used by:** Security gateway agent loop when `TOOL_ROUTER_ENABLED=true`.
  The router proposes at most one tool call before the main LLM runs. On any
  error, the loop falls back to the single-model (Black-Onyx-5B) path.
- **Strengths:** Fast tool selection. The main LLM (Black-Onyx-5B) uses the
  control-token format for tool calls; the router uses the OpenAI
  tool-calling API to pre-select tools.
- **Note:** Disabled by default. Enable with:
  ```powershell
  docker compose -f docker-compose.yml -f docker-compose.security-tools.yml \
    --profile tool-router up -d
  ```
  Then set `TOOL_ROUTER_ENABLED=true` in `.env` and restart the security gateway.

### Detection Modality Models (Streaming Scorers)

These are **not** LLMs. They are ONNX/sklearn anomaly detection models that
score streaming features from Kafka. They run on their own services and are
completely separate from the security tooling LLM pipeline.

| Model | Service | Port | Algorithm |
| --- | --- | --- | --- |
| log-model | `log-model` | 8090 | Log template-sequence Transformer + ONNX |
| network-model | `network-model` | 8101 | Flow Transformer + ONNX |
| metrics-model | `metrics-model` | 8102 | Metric Transformer + IsolationForest + ONNX |
| code-model | `code-model` | 8103 | Hybrid sklearn change-risk scorer |
| host-state-model | `host-state-model` | 8104 | Pass-through calibrated scorer |

These models participate in: `Kafka → inference-worker → model-gateway →
POST /v1/predict → findings.* → correlation-engine → incidents`.

### Malware-static (In-Process Library)

- **What:** EMBER-style PE static analysis model (ONNX + heuristics).
- **Format:** ONNX
- **Used by:** `malware-triage` service (imported in-process, not an HTTP
  service).
- **Config:** `MALWARE_TRIAGE_EMBER_ONNX_PATH` env var.

## Compose Services

The security tooling models are defined in `docker-compose.security-tools.yml`:

| Service | Container | Image | Purpose |
| --- | --- | --- | --- |
| `llama-server` | `blackonyx-llama-server` | `ghcr.io/ggml-org/llama.cpp:server-cuda` | Black-Onyx-5B GGUF + mmproj |
| `vllm-antares` | `blackonyx-vllm-antares` | `vllm/vllm-openai:v0.10.2` | Antares-1B safetensors |
| `tool-router` | `blackonyx-tool-router` | `ghcr.io/ggml-org/llama.cpp:server-cuda` | FunctionGemma 270M GGUF (optional) |
| `security-gateway` | `blackonyx-security-gateway` | Built from `services/security-gateway/` | Agent loop + tool dispatch |
| `security-runner` | `blackonyx-security-runner` | Built from `services/security-runner/` | Ephemeral container execution |

## File Locations

| Model | Directory |
| --- | --- |
| Black-Onyx-5B (GGUF + mmproj + chat template) | `models/Black-Onyx-5B/` |
| FunctionGemma 270M (GGUF) | `models/tool-router/` |
| Antares-1B (safetensors + CLI) | `detection/models/antares-1b/` |
| Log model (ONNX + code) | `detection/models/log-model/` |
| Network model (ONNX + code) | `detection/models/network-model/` |
| Metrics model (ONNX + code) | `detection/models/metrics-model/` |
| Code model (sklearn + code) | `detection/models/code-model/` |
| Host-state model (code) | `detection/models/host-state-model/` |
| Malware-static (ONNX + code) | `detection/models/malware-static/` |

## Model Download and Setup

### Black-Onyx-5B (required for chat and security agent)

The main LLM. Download two files into `models/Black-Onyx-5B/`:

```powershell
mkdir models\Black-Onyx-5B -Force

# 1. Main model: Q8_0 GGUF (4.9 GB)
#    Download from Hugging Face: Clownstein/Black-Onyx-5B-GGUF
#    File: Black-Onyx-5B-Q8_0.gguf
#    Place at: models/Black-Onyx-5B/Black-Onyx-5B-Q8_0.gguf

# 2. Multimodal projector (987 MB)
#    File: Black-Onyx-5B-mmproj.gguf
#    Place at: models/Black-Onyx-5B/Black-Onyx-5B-mmproj.gguf
```

Verify:
```powershell
dir models\Black-Onyx-5B\
# Should show: Black-Onyx-5B-Q8_0.gguf, Black-Onyx-5B-mmproj.gguf
```

### FunctionGemma 270M (optional tool router)

Download the Q8_0 GGUF into `models/tool-router/`:

```powershell
mkdir models\tool-router -Force

# Download from Hugging Face: google/functiongemma-270m-it (GGUF Q8_0)
# File: functiongemma-270m-it-Q8_0.gguf (278 MB)
# Place at: models/tool-router/functiongemma-270m-it-Q8_0.gguf
```

Enable with `--profile tool-router` and `TOOL_ROUTER_ENABLED=true` (see
[DEPLOYMENT.md](docs/DEPLOYMENT.md)).

### Antares-1B (vulnerability localization)

The Antares-1B model ships with the repository in safetensors format:

```
detection/models/antares-1b/model.safetensors   (3.5 GB)
```

No download needed; it ships with the repository. The `vllm-antares` service loads it
automatically.

### Detection modality models

All detection modality models (log, network, metrics, code, host-state,
malware-static) ship with the repository under `detection/models/`. No additional
download is required.

## Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_BASE_URL` | `http://llama-server:8081` | Main LLM endpoint (security gateway) |
| `LLM_MODEL_NAME` | `Black-Onyx-5B:Q8_0` | Main LLM model name |
| `LLM_TIMEOUT` | `300` | LLM request timeout (seconds) |
| `ANTARES_ENDPOINT` | `http://vllm-antares:8000/v1` | Antares completions endpoint (code-enrichment-worker) |
| `TOOL_ROUTER_ENABLED` | `false` | Enable FunctionGemma tool router |
| `TOOL_ROUTER_BASE_URL` | `http://tool-router:8080` | Tool router endpoint |
| `TOOL_ROUTER_MODEL` | `functiongemma-270m-it` | Tool router model name |

## Usage

### Start all model services

```powershell
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml up -d
```

### Start with the optional tool router

```powershell
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml \
  --profile tool-router up -d
```

Then set `TOOL_ROUTER_ENABLED=true` in `.env` and restart the security gateway:
```powershell
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml \
  up -d security-gateway
```

### Verify model health

```powershell
# From inside the security gateway container
docker exec blackonyx-security-gateway python -c "
import urllib.request, json, os
key = os.environ.get('SECURITY_GATEWAY_KEY','')
req = urllib.request.Request('http://127.0.0.1:8000/health/llm')
req.add_header('Authorization', f'Bearer {key}')
print(json.loads(urllib.request.urlopen(req).read()))
"
```
