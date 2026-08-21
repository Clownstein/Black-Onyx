# Cursor Rules, AGENTS.md, Subagents & Skills

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


Reference guide distilled from [Cursor Rules](https://cursor.com/docs/rules), [Skills](https://cursor.com/docs/skills), [Subagents](https://cursor.com/docs/subagents), and [Customize](https://cursor.com/docs/customize-cursor). Use this when creating or optimizing agent guidance in a project.

---

## Mental model: which tool when?

| Need | Use |
| --- | --- |
| Persistent coding standards, architecture, style | **Rules** or **AGENTS.md** |
| Simple project-wide instructions (no frontmatter) | **AGENTS.md** |
| File-scoped or always-on structured guidance | **Project Rules** (`.mdc`) |
| One-shot / repeatable workflow (changelog, deploy, review) | **Skill** |
| Long research, parallel work, isolated context | **Subagent** |
| Independent verification of claimed work | **Subagent** (e.g. verifier) |

**Rules vs Skills vs Subagents**

- **Rules** — Always (or often) in context. Shape *how* the agent behaves.
- **Skills** — Loaded when relevant (or via `/name`). Teach *how to do a task*.
- **Subagents** — Separate context window. Delegate *multi-step or noisy work*.

If a task is single-purpose and finishes in one shot → skill.  
If it needs isolation, parallelism, or specialized multi-step expertise → subagent.  
If it should constrain every (or matching) chat → rule / AGENTS.md.

---

## 1. Rules

Rules inject persistent instructions into Agent (Chat) context. LLMs do not retain memory between completions; rules are the durable layer.

**Rules do not affect** Cursor Tab or Inline Edit (Cmd/Ctrl+K). User Rules apply only to Agent Chat.

### Four rule types

| Type | Where | Scope |
| --- | --- | --- |
| **Project Rules** | `.cursor/rules/*.mdc` | This repo; version-controlled |
| **User Rules** | Customize → Rules | All projects for you |
| **Team Rules** | Cursor dashboard | Org-wide (Team/Enterprise) |
| **AGENTS.md** | Project root / nested dirs | Plain markdown alternative |

**Precedence when guidance conflicts:** Team Rules → Project Rules → User Rules. All applicable rules are merged; earlier sources win on conflicts.

### Project rules (`.mdc`)

Must use the `.mdc` extension. Plain `.md` files in `.cursor/rules` are **ignored** (no frontmatter). Prefer folders for organization:

```
.cursor/rules/
  react-patterns.mdc
  frontend/
    components.mdc
```

#### Application modes (frontmatter)

| UI type | `alwaysApply` | `description` | `globs` | Behavior |
| --- | --- | --- | --- | --- |
| Always Apply | `true` | — | — | Every chat; globs/description ignored |
| Apply to Specific Files | `false` | — | set | Auto-attach when matching files are in context |
| Apply Intelligently | `false` | set | omitted | Agent pulls in when description matches task |
| Apply Manually | `false` | omitted | omitted | Only when `@`-mentioned (e.g. `@my-rule`) |

```yaml
---
description: RPC service conventions for the backend
alwaysApply: false
---
```

```yaml
---
globs: src/components/**/*.tsx
alwaysApply: false
---
```

```yaml
---
alwaysApply: true
---
```

#### Glob tips

Separate multiple patterns with commas:

| Pattern | Matches |
| --- | --- |
| `**/*.ts` | All `.ts` files |
| `src/**/*.tsx` | `.tsx` under `src/` |
| `docs/**/*.md, docs/**/*.mdx` | Markdown under `docs/` |
| `tailwind.config.*` | Config with any extension |

#### Creating rules

1. `/create-rule` in Agent chat — generates frontmatter + file under `.cursor/rules`
2. **Customize → Rules → Add Rule**
3. Remote import: Customize → Rules → **Remote Rule (Github)** → syncs `.mdc` into `.cursor/rules/imported/<repoName>/`

#### Referencing files

Use `@filename.ts` inside a rule to pull templates/examples into context instead of pasting code. Keeps rules short and avoids staleness.

### Team Rules

- Free-form text (not `.mdc` folders); managed in [dashboard](https://cursor.com/dashboard/team-content)
- Optional globs (e.g. `**/*.py`) for file-scoped application
- **Enable immediately** vs draft; **Enforce** = required, cannot be toggled off by members
- Use for org standards/compliance — not as the only security control

### User Rules

Global preferences (tone, personal conventions). Example: “Reply concisely. Avoid filler.”

### Rule best practices

**Do**

- Keep each rule under **500 lines**; split large topics into composable rules
- One concern per rule; write like clear internal docs
- Give concrete examples or `@` file references
- Add a rule only after Agent repeats the same mistake
- Check rules into git; update when Agent errs (optional: `@cursor` on GitHub issues/PRs)

**Don't**

- Paste entire style guides (use linters; Agent already knows common style)
- Document every CLI the agent already knows (npm, git, pytest)
- Encode rare edge cases
- Duplicate code from the repo — point at canonical examples

### FAQ (rules)

- **Not applying?** Intelligent → need `description`. File-scoped → globs must match files in context.
- **Reference other rules/files?** Yes — `@file` in the rule; `@rule-name` in chat for manual apply.
- **Create from chat?** Yes — ask Agent or use `/create-rule`.

---

## 2. AGENTS.md

Plain markdown agent instructions. No frontmatter. Best for simple, readable project guidance without `.mdc` overhead.

**Locations:** project root and any subdirectory. Nested files apply when working in that directory (or children). Parent + child instructions combine; **more specific (deeper) wins** on conflicts.

```
project/
  AGENTS.md                 # global
  frontend/
    AGENTS.md               # frontend
    components/
      AGENTS.md             # components
  backend/
    AGENTS.md
```

Example content:

```markdown
# Project Instructions

## Code Style
- Use TypeScript for all new files
- Prefer functional components in React

## Architecture
- Follow the repository pattern
- Keep business logic in service layers
```

**When to prefer AGENTS.md vs `.cursor/rules`**

- AGENTS.md → few global instructions, human-readable, no need for globs/alwaysApply
- `.cursor/rules` → many scoped rules, intelligent apply, templates, team imports

---

## 3. Skills

[Agent Skills](https://agentskills.io/) — portable packages that teach domain workflows. Discovered at startup; Agent applies when relevant, or you invoke with `/skill-name`.

### Discovery paths

| Location | Scope |
| --- | --- |
| `.cursor/skills/`, `.agents/skills/` | Project |
| `~/.cursor/skills/`, `~/.agents/skills/` | User (all projects) |
| `.claude/skills/`, `.codex/skills/` (+ user home variants) | Compatibility |

Also: nested `.cursor/skills/` under packages in a monorepo — auto-scoped to that directory tree (like `paths`).

Never put custom skills in `~/.cursor/skills-cursor/` (Cursor built-ins).

### Layout

```
.cursor/skills/deploy-app/
  SKILL.md              # required
  scripts/              # optional executables
  references/           # optional deep docs (load on demand)
  assets/               # optional templates/data
```

Category folders are organizational only; identity = folder that contains `SKILL.md`.

### SKILL.md frontmatter

| Field | Required | Purpose |
| --- | --- | --- |
| `name` | Yes | Lowercase, hyphens; must match parent folder |
| `description` | Yes | WHAT + WHEN — agent uses this for relevance |
| `paths` | No | Globs; only surface when matching files in play |
| `disable-model-invocation` | No | `true` = slash-command only (`/name`) |
| `metadata` | No | Arbitrary key-value |

Legacy `globs` still works; prefer `paths`.

```yaml
---
name: react-component-patterns
description: Conventions for React components in this codebase. Use when editing .tsx components or UI packages.
paths:
  - "**/*.tsx"
  - "packages/ui/**/*.ts"
---
```

### Skill authoring best practices

1. **Description is critical** — third person; include trigger terms (WHAT and WHEN).
2. **Concise** — agent is already smart; only add what it wouldn't know. Keep `SKILL.md` under ~500 lines.
3. **Progressive disclosure** — essentials in `SKILL.md`; details in `references/` linked one level deep.
4. **Scripts** — prefer tested scripts over generated one-offs; document how to run them; relative paths from skill root; no Windows-style `\` paths.
5. **Degrees of freedom** — high for judgment tasks; low (exact scripts) for fragile ops.
6. **`disable-model-invocation: true`** when the skill should never auto-fire (explicit `/` only).

### Migrating to skills

`/migrate-to-skills` converts:

- Dynamic (“Apply Intelligently”) rules → skills
- Slash commands → skills with `disable-model-invocation: true`

Does **not** migrate: `alwaysApply: true` rules, glob-attached rules, or User Rules.

### Built-in skills (examples)

`/create-rule`, `/create-skill`, `/create-subagent`, `/migrate-to-skills`, `/babysit`, `/review`, `/loop`, `/canvas`, and others — type `/` in chat to list.

---

## 4. Subagents

Specialized assistants with **their own context window**. Parent sends a self-contained prompt (no prior chat history). Results return as a final message.

Available in editor, CLI, and Cloud Agents.

### Why use them

- **Context isolation** — noisy search/logs/DOM stay out of the main thread
- **Parallelism** — multiple subagents at once
- **Specialization** — custom prompts, models, readonly mode
- **Cost** — e.g. Explore uses a faster model for many searches

### Built-in (automatic)

| Subagent | Role |
| --- | --- |
| **Explore** | Codebase search/analysis (fast model, parallel) |
| **Bash** | Shell command series (verbose output isolated) |
| **Browser** | Browser MCP; filters DOM/screenshots |

No config needed; Agent launches them when appropriate.

### Custom subagents

| Scope | Paths |
| --- | --- |
| Project | `.cursor/agents/`, `.claude/agents/`, `.codex/agents/` |
| User | `~/.cursor/agents/`, `~/.claude/agents/`, `~/.codex/agents/` |

Precedence: project over user; `.cursor/` over `.claude/` / `.codex/` on name clash.

```markdown
---
name: security-auditor
description: Security specialist. Use when implementing auth, payments, or handling sensitive data.
model: inherit
readonly: true
---

You are a security expert auditing code for vulnerabilities.
...
```

| Field | Default | Notes |
| --- | --- | --- |
| `name` | from filename | lowercase-hyphens |
| `description` | — | **Delegation trigger** — invest here; phrases like “use proactively” help |
| `model` | `inherit` | Or specific ID; optional params e.g. `claude-opus-5[effort=high,context=300k]` |
| `readonly` | `false` | No edits / state-changing shell |
| `is_background` | `false` | Non-blocking |

**Foreground** — wait for result (sequential). **Background** — return immediately (long/parallel). Output for background agents: `~/.cursor/subagents/`.

### Invoking

- Automatic — based on task + descriptions
- Explicit — `/verifier confirm the auth flow` or natural language (“use the verifier subagent…”)
- Parallel — ask for parallel workstreams; Agent issues multiple Task calls
- Resume — pass agent ID to continue with preserved context
- Cloud — `/in-cloud` for VM+branch isolation; `/babysit` for PR babysitting

### Nesting

Since Cursor 2.5, subagents can spawn children (limited depth). A grandchild cannot spawn further. Hooks/tool policy can block spawning.

### Common patterns

1. **Verifier** — skeptical check that “done” work actually works (tests, edge cases)
2. **Orchestrator** — Planner → Implementer → Verifier with structured handoffs
3. **Debugger / test-runner** — focused failure loops

### Subagent best practices

**Do**

- One clear responsibility per agent
- Write specific descriptions; test whether the right agent is chosen
- Keep prompts short and direct
- Version-control `.cursor/agents/`
- Start with Agent-generated drafts (`/create-subagent`), then refine
- Start with 2–3 agents; add only for distinct use cases

**Don't**

- Dozens of vague “helper” agents
- 2,000-word prompts
- Subagents for one-shot tasks better served by skills/commands
- Expect speed wins on tiny tasks — isolation has startup overhead; parallel runs multiply tokens

### Cost trade-offs

| Benefit | Cost |
| --- | --- |
| Context isolation | Startup / re-gathering context |
| Parallelism | ~N× tokens for N agents |
| Specialized focus | Can be slower than main agent for simple work |

---

## 5. Optimization playbook

### Start lean

1. Begin with a short **AGENTS.md** or one always-apply rule for non-negotiables.
2. When Agent repeats a mistake → add a focused rule or skill.
3. When a workflow is repeated manually → extract a **skill** (`/create-skill`).
4. When research/verification blows up context → add a **subagent**.

### Write for the model’s decision layer

| Artifact | Decision field | Make it |
| --- | --- | --- |
| Intelligent rule | `description` | Specific domain + when to apply |
| Skill | `description` (+ optional `paths`) | WHAT + WHEN + trigger keywords |
| Subagent | `description` | Exact delegation scenarios |

Vague descriptions = never applied or wrongly applied.

### Scope aggressively

- Rules: globs or intelligent apply instead of always-on everything
- Skills: `paths` or nested package skills for monorepos
- Subagents: `readonly: true` for audit/review roles

### Keep context small

- Reference files with `@` instead of pasting
- Skills: progressive disclosure via `references/`
- Split mega-rules into composable `.mdc` files
- Prefer skills for procedural content that shouldn’t sit in every prompt

### Team sharing

- Commit `.cursor/rules`, `.cursor/skills`, `.cursor/agents`, `AGENTS.md`
- Team Rules for org-wide must-haves; enforce only what’s truly required
- Import remote rules/skills from GitHub via Customize when reusing configs

### Choose the right layer (cheat sheet)

```
Persistent “never do X / always do Y”     → Rule (or AGENTS.md)
“When editing *.tsx, follow these steps”  → Rule with globs OR Skill with paths
“/deploy staging” style workflow          → Skill (often disable-model-invocation)
Long explore / parallel / verify          → Subagent
```

---

## 6. Quick file map

```
project/
  AGENTS.md                          # simple global agent instructions
  frontend/AGENTS.md                 # nested, more specific
  .cursor/
    rules/
      api.mdc                        # project rules (.mdc + frontmatter)
      imported/<repo>/...            # remote imports
    skills/
      my-skill/SKILL.md              # skills (+ scripts/, references/)
    agents/
      verifier.md                    # custom subagents
```

Manage visibility and toggles from **Customize** in the sidebar (Rules, Skills, Subagents, Hooks, Commands, Plugins, MCP).

---

## Sources

- https://cursor.com/docs/rules
- https://cursor.com/docs/skills
- https://cursor.com/docs/subagents
- https://cursor.com/docs/customize-cursor
- https://agentskills.io/
