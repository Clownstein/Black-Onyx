# Black Onyx immersive UI template

> **Status:** the Gallery hub at `/` and related site/credential APIs are implemented. Treat remaining checklist items as polish backlog; see [docs/FEATURES.md](docs/FEATURES.md).

Reference observed live: [Phantom Studios](https://www.phantom.land/) (Next.js App Router + full-viewport WebGL canvas for the Work grid; HTML detail routes for projects).

This document describes how Black Onyx adopts an immersive gallery interaction model without copying Phantom’s branding or content.

---

## What we observed on Phantom.land

### Home / “Work” surface
- **Full-bleed black void** with a **curved media grid** (cylindrical / spherical projection). Center tiles face the camera; edge tiles foreshorten and vignette.
- **Drag-to-pan** (hold primary button, move mouse): pans the grid in **X and Y** with inertia. Not a normal document scroll.
- **DOM links exist for a11y** (`/projects/...`) but are `pointer-events: none`; the **canvas** owns hit-testing (drag vs click threshold).
- **Fixed chrome floats above the canvas**:
  - Top-left logo
  - Top-center **FILTER** pill
  - Top-right primary CTA pill (**LET’S TALK**)
  - Mid-left vertical pill: **grid vs list** view toggle
  - Mid-right **SOUND [ON/OFF]**
  - Bottom-center glassmorphic pill: **Work / About / Careers** (active segment filled white)

### Tile → detail
- Clicking a tile (short press, little movement) routes to a **dedicated project page** (e.g. `/projects/johnnie-walker-festive-greetings`).
- Detail pages drop the WebGL grid: **hero title**, brand lockups, long-form “ABOUT”, feature tags, related work, same bottom nav + CTA.
- **Back** (browser history or **Work** nav) returns to the immersive grid and restores pan state (or a sensible default).

### Interaction loop verified
1. Drag left / right / up / down → grid contents change under the fixed chrome.
2. Click a tile → project detail URL + hero layout.
3. Return to Work → grid again.
4. Pan, click another tile → second detail route.

---

## Design intent for Black Onyx

Keep Black Onyx’s product jobs (ingest, IOC workbench, ATT&CK, cases, feeds, etc.) but present the **authenticated workspace hub** as an immersive “intel gallery” instead of only a dense left-rail dashboard.

| Phantom concept | Black Onyx analog |
| --- | --- |
| Project tiles | **Every** app page as a tile, plus user-added external sites |
| FILTER | Section, status, built-in vs saved sites, text search |
| LET’S TALK | **Add site** / **New case** / **Ask chat** / **Ingest** (role-aware) |
| Work / About / Careers | **Investigate** / **Intelligence** / **Operations** / **Sites** / **Control** |
| Grid ↔ list toggle | Immersive canvas ↔ current sidebar+list layout (escape hatch) |
| SOUND | Optional ambient “ops room” audio or mute for alert chimes |
| Project detail page | Internal routes (`/iocs`, …) **or** external site launcher / embedded session |

**Hard requirement:** immersive mode is an **optional shell**. Analysts must always be able to switch to the current form-heavy UI for power workflows (forms, tables, JSON). Do not trap critical CRUD behind WebGL only.

**Coverage requirement:** the gallery must surface **all** Black Onyx pages listed in [Complete page → tile map](#complete-page--tile-map). Users can also **add external sites**, optionally **save login material**, and get a new tile they can pan to and open.

---

## Visual language (Black Onyx-skinned)

Reuse Phantom’s *structure*, skinned to the shipped Black Onyx kit ([docs/brand/README.md](docs/brand/README.md)):

- **Background:** deep charcoal void (`#0B0B0E`) with violet radial lift; auth uses `BlackOnyxBackground.png`.
- **Accent:** primary violet `#6C3CF2` / glow `#A78BFA`; silver `#A9ADB6` for secondary type.
- **Tiles:** 16:10 or square cards with:
  - Status strip (LIVE / DEGRADED / EMPTY)
  - Title + one-line subtitle
  - Mini preview (sparkline, heatmap thumbnail, IOC count, last poll time)
- **Chrome pills:** frosted glass (`backdrop-filter: blur(12px)`), 999px radius, high-contrast active state (filled violet or white on dark).
- **Typography:** keep Black Onyx’s current stack in app mode; for the hub only, a sharper display face for tile titles is fine if licensed.
- **Motion (2–3 intentional):**
  1. Inertial pan of the gallery
  2. Tile hover lift / focus ring
  3. Enter detail: brief scale+fade of selected tile into route transition

---

## Functional architecture

### Layers
```
┌─────────────────────────────────────────────┐
│ Fixed chrome (logo, filter, CTA, section pill)│
├─────────────────────────────────────────────┤
│ ImmersiveGallery (WebGL or CSS-3D)           │
│   camera/offset (x,y) + tile instances       │
│   pointer: drag → pan; click → navigate      │
├─────────────────────────────────────────────┤
│ Parallel a11y DOM: <a href> for every tile   │
│ (visually hidden or pointer-events:none)     │
└─────────────────────────────────────────────┘
```

### Recommended tech (fits current React + Vite UI)

**Research (2026-07-31):** Black Onyx web is React **19.1** (`web/package.json`). R3F major versions must pair with React: **`@react-three/fiber@9` ↔ React 19** (fiber@8 is React 18 only) — see [R3F introduction](https://r3f.docs.pmnd.rs/getting-started/introduction). Install set:

```bash
npm install three @types/three @react-three/fiber@9 @use-gesture/react
```

1. **Preferred for fidelity:** React Three Fiber (fiber only — **no drei**)  
   - Grid of textured planes wrapped onto a **concave sphere** (arc-length mapping, so gutters stay even as tiles curl); a cylinder only bends in X and does not sell the effect  
   - **The curve goes inward, not outward.** Put the sphere's centre on the camera's side (`z = +R`, camera inside it at `CAM_DIST < 2R`) so rim tiles bow *toward* the viewer and rotate to face them — standing inside a curved screen. Centre at `z = -R` with the camera outside gives a convex bulge with the rim receding, which is the outside of a ball and reads as wrong immediately. The tell in code is the sign pair: inward is `z = R - R·cosφ·cosθ` with rotation `(φ, -θ, 0)`; outward is `z = R·cosφ·cosθ - R` with `(-φ, θ, 0)`. Note that concave is inherently a *subtler* look than convex — it reduces rim foreshortening rather than exaggerating it — so resist the urge to "fix" it by flipping back.  
   - Recycle a fixed mesh pool across an infinite wrapped lattice rather than mounting one mesh per tile; the world repeats on a block sized from the tile count  
   - Disable default OrbitControls; pan a shared offset and damp it toward its target per frame. Plain `x += (target - x) * (1 - exp(-k*dt))` is frame-rate independent and needs no helper library — `maath`'s `easing.damp` does the same thing and is not worth a dependency for one call site  
   - **Do not add `@react-three/drei`.** It was tried and removed: the only things used from it were `PerspectiveCamera` (replaceable by `<Canvas camera={{...}}>`) and `PerformanceMonitor` (~25 lines of `useFrame`), and it drags in 21 direct dependencies — including `@mediapipe/tasks-vision` and `hls.js` — several of which default to fetching assets from third-party CDNs. That is a poor trade for a security tool with `default-src 'self'`, and its bundled output also tripped endpoint AV as a false positive. See `AdaptiveResolution` in `web/src/gallery/Scene.tsx`.  
   - Projecting live DOM into the scene per tile (drei's `Html`) tanks FPS at dozens of tiles anyway — rasterize tiles to canvas textures instead (`web/src/gallery/tile_texture.ts`)  
   - Pause the Canvas when a detail route mounts (`frameloop="demand"` or unmount Canvas).
2. **Lighter alternative (phase 2):** CSS `perspective` on a wrapper + large absolute grid; columns get `rotateY` proportional to distance from viewport center; pan via `translate3d` on the grid. Good enough for Phantom-like *feel* without WebGL; sphere fidelity is lower.
3. **Gestures:** `@use-gesture/react` `useDrag` (docs: [Gesture options](https://use-gesture.netlify.app/docs/options/)):
   - Set **`filterTaps: true`** (modern name for filtering taps vs drag; earlier APIs used `filterClicks`) so small movements do not steal navigation clicks.
   - Optional **`threshold: 8`–`12`** (px) so pan only starts after intentional movement — matches Phantom’s drag-vs-click behavior observed on the canvas.
   - Do **not** lock `axis` to `x` or `y`; Phantom pans freely in both directions.
   - On `last` + tap / non-intentional: `navigate(href)`.
   - **Trap:** do not reset your drag-vs-tap flag on the gesture's `first` event. With a non-zero `threshold`, use-gesture skips the handler entirely below it, and its engine returns out of `compute()` before assigning `state.first` on any unintentional gesture — so once the user has completed one real pan, `first` is stuck `false` forever and the flag never clears. Symptom: every tile becomes permanently unclickable after the first drag. Clear the flag on the raw `pointerdown` (which always fires) and set it from the gesture's own `tap` verdict on release. Covered by the "tiles stay clickable after the user has panned" e2e test.
4. **Routing:** keep React Router 7. Detail pages = existing workflows. Store gallery offset in `sessionStorage` so Back restores pan.
5. **No Three.js in v1 forms** — gallery shell only; workflows stay DOM.

### Data for tiles
Each tile is a small view-model, not a screenshot of the full page:

```ts
type GallerySection =
  | "investigate"
  | "intelligence"
  | "operations"
  | "control"
  | "sites"        // user-added external destinations
  | "auth";        // signed-out only, if hub is shown pre-login

type GalleryTile = {
  id: string;
  kind: "builtin" | "external";
  href: string;           // internal "/iocs" or external "https://…"
  section: GallerySection;
  title: string;
  subtitle: string;
  badge?: "LIVE" | "ALERTS" | "EMPTY" | "SAVED" | "LOCKED";
  preview: "metric" | "heatmap" | "list" | "image" | "favicon" | "color";
  metrics?: Record<string, string | number>;
  roles?: Array<"admin" | "analyst" | "viewer">;
  // External / saved-site fields (kind === "external")
  openMode?: "new_tab" | "embedded" | "launcher";
  faviconUrl?: string;
  credentialId?: string;  // points at vault entry; never embed secrets in the tile
  tags?: string[];
  createdAt?: string;
  updatedAt?: string;
};
```

Built-in tiles populate from existing APIs (`/capabilities`, `/feeds`, `/cases`, `/decay/tracked`, `/attack/heatmap`, collections count, etc.) on a slow poll. External tiles load from the per-user **Sites** store (see below).

### Filter model
Filter pill opens a floating panel (not a modal trap):

- Section (Investigate / Intelligence / Operations / Sites / Control)
- Origin (built-in app pages vs user-added sites)
- Status (has alerts, empty, healthy, has saved login)
- Text match on title / subtitle / URL / tags

Filtering **does not reload the world**—it dims/hides tiles and optionally eases camera toward the first match.

### Section pill behavior
Bottom pill segments: **Investigate** · **Intelligence** · **Operations** · **Sites** · **Control** (Control only if admin).

Selecting a segment should either:
- **A (recommended):** animate pan toward that cluster of tiles, or  
- **B:** swap tile set while keeping the same chrome  

Match Phantom: chrome stays; content under it changes. Primary CTA on the Sites segment defaults to **Add site**.

---

## Complete page → tile map

Every current Black Onyx route must appear as a gallery tile (role-filtered). Detail view = existing workflow under shared immersive chrome.

### Auth (pre-login / account flows)
These are usually **outside** the authenticated hub. If a signed-out “portal” hub is used, include them; otherwise keep classic auth screens and land on the gallery after login.

| Tile | Route | Notes |
| --- | --- | --- |
| Sign in | `/` (unauthenticated) | Classic auth card acceptable |
| Accept invitation | `/register?token=…` | Token from invite email |
| Forgot password | `/forgot-password` | |
| Reset password | `/reset-password?token=…` | |

### Overview
| Tile | Route | Preview idea | Roles |
| --- | --- | --- | --- |
| Dashboard | `/` | Collections / jobs / Qdrant health | all |
| Jobs | `/jobs` | Active ingestion jobs | admin, analyst |

### Investigate
| Tile | Route | Preview idea | Roles |
| --- | --- | --- | --- |
| Ingest | `/ingest` | Last upload / job status | admin, analyst |
| Search | `/search` | Recent query chips | all |
| Image search | `/image-search` | Thumbnail placeholder | all |
| Collections | `/collections` | Point counts | all |
| Chat | `/chat` | Active session count | admin, analyst |

### Intelligence
| Tile | Route | Preview idea | Roles |
| --- | --- | --- | --- |
| IOC workbench | `/iocs` | Last extracted types | admin, analyst |
| ATT&CK | `/attack` | Top-10 heatmap thumb | all |
| Graph | `/graph` | Node/edge counts | all |
| Rules | `/rules` | Last generated format | admin, analyst |
| Reports | `/reports` | Shared report count | all |

### Operations
| Tile | Route | Preview idea | Roles |
| --- | --- | --- | --- |
| Cases | `/cases` | Open case count | all |
| Watchlists | `/watchlists` | Unacked alerts | all |
| Feeds | `/feeds` | Feed health / last poll | all |
| Decay | `/decay` | Fresh vs stale bars | all |
| Bookmarks | `/bookmarks` | Bookmark count | all |
| System | `/system` | Capability flags | all |

### Control (admin)
| Tile | Route | Preview idea | Roles |
| --- | --- | --- | --- |
| Administration | `/admin` | User / invite counts | admin |
| Settings | `/settings` | Provider / enrichment status | admin |

### Sites (user-added)
| Tile | Route / target | Preview idea | Roles |
| --- | --- | --- | --- |
| *(dynamic)* | user HTTPS URL | Favicon + title + SAVED/LOCKED badge | owner (private) |
| Add site | opens create panel | “+” tile always at end of Sites cluster | all authenticated |

When a new built-in page is added to the product, it **must** get a corresponding gallery tile entry in this map and in the tile registry code.

---

## User-added sites & saved logins

Goal: analysts can pin **external consoles** (SIEM, EDR, ticketing, cloud consoles, wiki, vendor portals, etc.) into the same immersive gallery, optionally store login material, and open them from a tile like any built-in page.

### Add site flow (UI)
1. CTA **Add site** (top-right on Sites segment, or “+” tile).
2. Form fields:
   - **Display name** (required)
   - **URL** (required, HTTPS only in production; allow `http://localhost` / private lab hosts when `security.production` is false)
   - **Section** (default `sites`; optional pin into Investigate / Intelligence / Operations clusters)
   - **Tags** (optional)
   - **Open mode**: `new_tab` (default) | `embedded` (sandboxed iframe when allowed) | `launcher` (hub page with Open + Copy + Fill helpers)
   - **Favicon** — prefer server-side fetch of the site’s own icons (`link[rel~=icon]` / `/favicon.ico`) cached under `/api/v1/sites/{id}/favicon` so CSP `img-src 'self'` stays tight. Fallback for labs: `https://www.google.com/s2/favicons?domain={host}&sz=64` ([documented public helper](https://dev.to/derlin/get-favicons-from-any-website-using-a-hidden-google-api-3p1e)) requires expanding CSP `img-src` to that host or proxying the bytes.
   - **Save login?** toggle
3. If Save login is on:
   - **Username / email**
   - **Password** (or API token / session secret)
   - Optional **notes** (MFA hint, tenant ID—not a second password field dump)
   - Optional **login page URL** if different from the site URL
4. On save: create vault entry + gallery tile; camera eases to the new tile.

### Saved login behavior
- Tile badge **SAVED** when a credential is linked; **LOCKED** until the user unlocks the vault for this session (re-auth or vault passphrase).
- Clicking the tile:
  - **new_tab:** open URL; optionally show a one-time “Reveal username / password” drawer (copy buttons) so the user can paste into the third-party login. Black Onyx **does not** silently POST passwords to third parties.
  - **launcher:** in-app page with Open Site, Copy username, Copy password (clipboard, short TTL clear), Edit, Delete.
  - **embedded:** see [Embedded mode constraints](#embedded-mode-constraints) below. Never inject credentials into the iframe DOM from automation that bypasses the user’s control.
- Edit / delete / rotate secret from tile context menu or launcher page.
- Credentials are **per-user**, never shared across accounts unless an explicit “shared team link” feature is designed later (out of scope for v1).

#### Clipboard “copy password” (research)
- Use `navigator.clipboard.writeText` only in a **secure context** (HTTPS or localhost) after a **user gesture** ([MDN Clipboard.writeText](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText)).
- After copy, schedule `setTimeout` (~30s) to call `writeText("")` (or a benign placeholder) to reduce shoulder-surfing / leftover clipboard risk. Clearing is best-effort; OS clipboard managers may retain history.
- Do not auto-copy on tile open.

#### Embedded mode constraints (research)
- **Target site** may send `X-Frame-Options: DENY` or `SAMEORIGIN`, or CSP `frame-ancestors 'none'|...` — browsers will refuse to embed ([MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)). Most SIEM/EDR consoles block framing → **default open mode should be `new_tab` or `launcher`**, not `embedded`.
- **Our page** must allow the iframe source via CSP **`frame-src`**. Today Black Onyx middleware sets CSP without `frame-src`, so it falls back to `default-src 'self'` ([MDN frame-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-src)) — embedded external sites **will not load** until CSP is extended (per-host allowlist or proxy). Keep `frame-ancestors 'none'` on our responses (already set) so others cannot frame Black Onyx.
- If embedding is attempted: use `<iframe sandbox="allow-scripts allow-forms allow-same-origin allow-popups">` only as needed; empty `sandbox` breaks most login UIs. Prefer probing with a HEAD/GET for `X-Frame-Options` / CSP before offering Embed as an option.

### Data model (server)

```ts
type UserSite = {
  site_id: string;
  owner_user_id: string;
  name: string;
  url: string;
  login_url?: string;
  section: GallerySection;
  tags: string[];
  open_mode: "new_tab" | "embedded" | "launcher";
  favicon_url?: string;
  credential_id?: string;
  created_at: string;
  updated_at: string;
};

type StoredCredential = {
  credential_id: string;
  owner_user_id: string;
  // ciphertext only at rest (AES/Fernet); never store a hash of the third-party secret
  username_encrypted: string;
  secret_encrypted: string;
  notes_encrypted?: string;
  // Argon2id (or HKDF) used to *derive* the data-encryption key — not to hash the site password
  kdf: "argon2id" | "hkdf-sha256";
  kdf_salt: string;
  created_at: string;
  updated_at: string;
  last_accessed_at?: string;
};
```

### Suggested API surface
| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/sites` | List current user’s site tiles (no secrets) |
| POST | `/api/v1/sites` | Create site (+ optional credential blob) |
| PATCH | `/api/v1/sites/{site_id}` | Update metadata / open mode |
| DELETE | `/api/v1/sites/{site_id}` | Remove tile and linked credential |
| POST | `/api/v1/sites/{site_id}/credential` | Create or rotate saved login |
| GET | `/api/v1/sites/{site_id}/credential` | Decrypt for owner after vault unlock (audited) |
| DELETE | `/api/v1/sites/{site_id}/credential` | Drop saved login only |

### Security requirements (non-negotiable)

**Research — OWASP Password Storage / Cryptographic Storage (2026-07-31):**

- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): login passwords for *this* app must be **hashed** (Argon2id). Black Onyx already does this via `argon2.PasswordHasher` in `AuthService`.
- The **same cheat sheet** states the rare case where **reversible encryption** is required: storing a secret that must later be recovered in plaintext to authenticate to *another* system. Saved third-party site logins are exactly that case — **encrypt, do not hash**, them.
- Prefer **AES-256 with an authenticated mode (GCM/CCM)** ([OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)). Black Onyx already uses **Fernet** (AES-CBC + HMAC, authenticated) for runtime secrets and MFA secrets (`runtime_settings.py`, `auth/service.py`) keyed from `BLACK_ONYX_AUTH_SECRET`. Reuse that pattern for site credentials **or** upgrade to AES-GCM with a per-user salt for clearer key separation.
- Derive a **per-user data key**: `HKDF/SHA-256(auth_secret, user_id + salt)` or Argon2id(user vault passphrase) → wrap Fernet/AES key. Store salt beside ciphertext; never store the passphrase.
- Separate keys from ciphertext when feasible; plan for **key rotation** (re-encrypt on secret rotate).
- Minimize what is stored (username + secret + optional notes only).
- Never return secrets from `GET /sites` list payloads.
- Audit every credential reveal / rotate / delete (`audit_events`).
- Rate-limit credential GET.
- HTTPS URL validation; block `javascript:`, data URLs, and unexpected schemes.
- Clipboard clear ~30s after copy (see above).
- Optional: require fresh session MFA step-up before reveal when the account has MFA enabled.
- Do **not** sync passwords to browser `localStorage` unencrypted.

### Gallery integration
- Sites cluster sits as its own band on the curved grid (or interleave if user pinned a site into another section).
- FILTER → Origin = “Saved sites” shows only user tiles.
- Empty Sites state: single **Add site** tile with short copy (“Pin SIEM, EDR, and vendor consoles here”).

---

## Detail pages (after tile click)

Do **not** rebuild every workflow as a marketing page. Pattern:

1. Shared **detail chrome**: logo → hub, section pill, primary CTA, optional “Exit immersive” → classic layout.
2. **Built-in tile:** existing workflow content mounts in `#main` (current `Heading` + forms).
3. **External tile:** launcher / new tab / embed per `open_mode` (see above).
4. Optional **hero strip** above the workflow (title + one sentence + LIVE badge)—inspired by Phantom’s project hero, but short.

Back behavior:
- Browser Back, or logo / hub segment returns to gallery with restored offset.

---

## Accessibility & ops constraints

- Every tile has a real `<a href>` (keyboard, screen readers, no-JS fallback list). External tiles use the real site URL (or launcher route) accordingly.
- Respect `prefers-reduced-motion: reduce`: disable inertia, sphere warp, and continuous `useFrame` rotation; fall back to CSS grid/list. Match media via `window.matchMedia("(prefers-reduced-motion: reduce)")` and also pause WebGL when the document is hidden (`document.visibilityState`).
- WebGL failure / low GPU: auto-fallback to list layout (same data, including user sites). Optional: an in-house FPS watcher to drop render resolution when frames slip (`AdaptiveResolution` in `Scene.tsx`) — not drei's `PerformanceMonitor`, see the tech note above.
- Auth/RBAC unchanged: hide built-in tiles the role cannot use (same rules as today’s sidebar). User sites remain private to the owner.
- **CSP (current vs needed):** middleware today uses roughly  
  `default-src 'self'; … img-src 'self' data: blob:; … frame-ancestors 'none'` with **no** `frame-src` / external `img-src`. For the gallery hub:
  - Keep `frame-ancestors 'none'`.
  - Add `frame-src` only for hosts the user explicitly enabled for embed (or omit embeds).
  - Prefer favicon **proxy** so `img-src` stays `'self'`; otherwise allowlist the favicon CDN.
  - R3F/WebGL needs no extra CSP script hosts if bundles stay same-origin; avoid `unsafe-eval` unless a dependency forces it (prefer not to).

---

## Performance budget

- Cap visible GPU tiles (~40–60); recycle textures when panning far.
- Prefer static thumbnails / canvas-rasterized tile textures over live iframe embeds **or** per-tile DOM projected into the scene.
- Pause gallery render loop when a detail route is mounted (`frameloop="demand"` / unmount Canvas).
- Target 60fps on mid-range GPUs; degrade to CSS layout on integrated graphics if FPS &lt; 30 for 2s (optional `PerformanceMonitor`).
- With `prefers-reduced-motion`, skip damping loops entirely.

---

## Phased delivery (suggested)

1. **Shell chrome only** — floating pills + list grid (no WebGL); **all built-in page tiles** from the map above.  
2. **CSS-3D / 2D drag canvas** — pan + click threshold + session restore.  
3. **Live tile metrics** from existing APIs.  
4. **User Sites CRUD** — add / edit / delete external tiles (no credentials yet).  
5. **Encrypted saved logins** — vault + reveal/copy/launcher flows + audit.  
6. **Optional R3F sphere** for fidelity once (2) is solid.  
7. **Filter + section clustering** + reduced-motion / fallback polish.

---

## Explicit non-goals (v1)

- Full Three.js rewrite of IOC forms, chat, or admin settings.
- Ambient audio as a default (opt-in only).
- Replacing STIX/JSON advanced editors with “pretty” tiles only.
- Pixel-perfect clone of Phantom branding, mascot, or project photography.
- Auto-login bots that submit third-party credentials without user action.
- Shared team password dump / org-wide credential browsing.

---

## Acceptance checklist (hub)

- [ ] Hold LMB and drag pans gallery in four directions with damping.
- [ ] Every built-in page in the complete map has a role-correct tile.
- [ ] Short click on a built-in tile navigates to the correct Black Onyx route.
- [ ] User can add an HTTPS site; a new tile appears and is reachable by pan/filter.
- [ ] User can save a login for a site; list APIs never return plaintext secrets.
- [ ] User can open / copy / edit / delete a saved site from the gallery or launcher.
- [ ] Browser Back returns to hub; pan position restored or reset intentionally.
- [ ] Section pill and FILTER change visible set / camera focus without full reload (including **Sites**).
- [ ] Grid ↔ list toggle preserves route map, role filtering, and user sites.
- [ ] Keyboard users can Tab through tile links and activate with Enter.
- [ ] Classic sidebar layout remains available for power workflows.

---

## Reference notes from live session

- Site: `https://www.phantom.land/` (Next.js `_next/static` chunks; Work view uses a single full-viewport `canvas`).
- Example detail routes opened during exploration:
  - `/projects/johnnie-walker-festive-greetings`
  - `/projects/stranger-things-hawkins-heroes-walking-tour`
- Detail pages share bottom **Work / About / Careers** pill and top CTA; immersive canvas is hub-only.
- Project link elements exist in the a11y tree with `pointer-events: none`; hit-testing is canvas-owned (drag threshold then click → client route).

---

## Research log (implementation gaps filled)

Collected 2026-07-31 via Firecrawl + local codebase review. Findings are folded into the sections above; this log is the source index.

| Topic | Source | Takeaway for Black Onyx |
| --- | --- | --- |
| R3F ↔ React 19 | [r3f.docs.pmnd.rs introduction](https://r3f.docs.pmnd.rs/getting-started/introduction) | Use `@react-three/fiber@9` with React 19; install `three` + types. |
| Drei `Html` | [drei Html docs](https://drei.docs.pmnd.rs/misc/html) | Evaluated and rejected along with the rest of drei — heavy for many tiles, and the dependency is not worth it. Tiles are canvas textures instead. |
| Drag vs click | [use-gesture options](https://use-gesture.netlify.app/docs/options/), [pmndrs/use-gesture#109](https://github.com/pmndrs/use-gesture/issues/109) | `filterTaps` + ~8–12px `threshold`; free 2D pan (no axis lock). |
| Inertia | R3F community (`maath` / `easing.damp`) | Damp pan velocity each frame; stop under `prefers-reduced-motion`. Implemented in-house — one exponential-decay line, no dependency. |
| Third-party password storage | [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Recoverable secrets ⇒ encrypt (not hash); Argon2id remains for Black Onyx login passwords. |
| Crypto at rest | [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | AES + authenticated mode; key separation/rotation. Align with existing Fernet usage or AES-GCM. |
| Framing / embed | [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options), [MDN frame-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-src) | Most vendor apps block iframes; need our `frame-src` allowlist; keep `frame-ancestors 'none'`. |
| Clipboard | [MDN writeText](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard/writeText) | Secure context + user gesture; timed clear is app policy. |
| Favicons | Google `s2/favicons?domain=&sz=` helper | Convenient but expands CSP or should be proxied through our API. |
| Current CSP | `auth/middleware.py` | `default-src 'self'`; no `frame-src`; `img-src 'self' data: blob:` — update before embeds/external favicons. |
| Existing crypto | `AuthService`, `RuntimeSettingsStore` | Argon2id password hashing + Fernet for secrets already in-tree — extend, don’t invent a parallel stack. |