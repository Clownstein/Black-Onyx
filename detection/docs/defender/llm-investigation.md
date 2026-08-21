# LLM investigation assistant (local / air-gap)

**Status:** UI draft assist ships in Incident detail (`InvestigationAssist`). A **local
markdown template** fallback is shipped when `/chat` fails. Full Ollama / Kafka auto-wiring
into correlation or response paths remains **out of scope**.

## Policy

Black Onyx may optionally use a **local** LLM (e.g. [Ollama](https://ollama.com/)) to help
analysts draft investigation notes. The assistant is **suggest-only**:

- Never auto-acknowledge, resolve, contain, or open TheHive cases.
- Never execute playbooks or Velociraptor collections.
- Never send incident payloads to public cloud LLM APIs when `airgap_mode` / air-gap policy is on.
- Analyst must copy/edit suggestions before posting comments or dispositions.

## Suggested setup

1. Run Ollama on a SOC workstation or internal GPU host (`ollama serve`).
2. Pull a small instruct model suitable for air-gap (operator choice).
3. Configure the Black Onyx server LLM provider (see TIP chat / settings); the UI calls `/api/v1/chat`.
4. Without a working chat provider, the UI falls back to a **local template draft** from
   incident title, severity, assets, findings, and evidence fields.
5. Display output as a draft textarea — no silent writes to incident-api.

## Prompt boundaries

Instruct the model to:

- Propose hypotheses and ATT&CK techniques as **possibilities**, not facts.
- List questions for the analyst / next VQL / log queries.
- Refuse instructions that ask it to “just block the IP” without human approval.

## Out of scope (this phase)

No production wiring of Ollama into correlation-engine, response approval, or the Kafka hot path.
Keep the assistant offline from automated detection pipelines.
