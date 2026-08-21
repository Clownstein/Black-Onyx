# Planned ideas

Ideas drawn from a gap analysis of Black Onyx against common TIP / SOC workflows (2025–2026), plus current open standards and free data sources.

**Status (implemented Aug 2026):** all five items below shipped in-tree.

**Research inputs (Aug 2026):**
- [Wiz — Threat intelligence platforms](https://www.wiz.io/academy/threat-intel/threat-intelligence-platforms)
- [Stellar Cyber — TIP landscape](https://stellarcyber.ai/learn/top-threat-intelligence-platforms/)
- [MISP project](https://www.misp-project.org/) and [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)
- [FIRST EPSS](https://www.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OpenAI Responses API migration](https://developers.openai.com/api/docs/guides/migrate-to-responses)
- [STIX / TAXII overview](https://www.cyware.com/resources/security-guides/what-do-stix-and-taxii-mean-in-cybersecurity)

---

## 1. Split OpenAI (Responses API) from OpenAI-compatible (Chat Completions) — DONE

- Settings: separate **OpenAI (Responses API)** and **OpenAI compatible (Completions)** cards.
- Provider `openai` always uses Responses against `api.openai.com`.
- Provider `openai_compatible` uses Chat Completions; rejects `api.openai.com` hosts.
- Existing `openai_compatible` + `api.openai.com` configs migrate to `openai` on load.

## 2. CVE intelligence layer: NVD + EPSS + CISA KEV — DONE

- Enrichment providers `nvd`, `epss`, `kev`; IOC type `cve` in enrich/score UI.
- Settings catalog toggles under Enrichment APIs.

## 3. MISP / community CTI bidirectional sync — DONE

- `MispSyncManager` + `/api/v1/misp/*` (status, sync, publish, configure).
- Sync stores event/IOC metadata and upserts extracted IOCs into a named watchlist.
- Feeds page MISP connection form; DigitalSide is not RSS so it is configured via MISP, not a preset.

## 4. Outbound TAXII 2.1 collections — DONE

- `TaxiiPublishManager` + public `/taxii2/*` (Bearer API keys).
- Operations → **Publishing** UI for collections, keys, and STIX publish.
- Management APIs under `/api/v1/taxii/*`.

## 5. Detection ops / SOAR-lite playbooks — DONE

- `PlaybookManager` + `PlaybookRunner` (enrich, create_case, notify_webhook, generate_sigma, wait_approval).
- Operations → **Playbooks** UI; webhook ingest can trigger `watchlist_alert` playbooks.
- Rules are still never executed locally.

---

## Explicitly out of scope (unchanged)

- Dark-web / credential-leak marketplaces.
- Running Sigma/YARA inside Black Onyx.
- Full CNAPP / cloud-asset correlation.
