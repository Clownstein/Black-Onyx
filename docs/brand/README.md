# Black Onyx brand kit

Canonical product identity for UI and documentation.

## Assets

| File | Use |
|---|---|
| [BlackOnyxBackground.png](../../BlackOnyxBackground.png) | Auth / splash background (also published as `/background.png`) |
| [BlackOnyxTransparentLogo.png](../../BlackOnyxTransparentLogo.png) | Horizontal lockup (also published as `/logo.png`) |

Repository-root copies of the background and logo are the Vite/Docker sources of truth. Prefer those filenames when updating artwork.

## Color tokens

| Token | Hex | Role |
|---|---|---|
| Deep background | `#0B0B0E` | App ground (`--bg`) |
| Dark grey | `#1A1A1F` | Panels (`--surface`) |
| Medium grey | `#2F3138` | Soft fills / borders (`--surface-soft`, `--border`) |
| Silver | `#A9ADB6` | Secondary text (`--muted-strong`) |
| Primary violet | `#6C3CF2` | Accent / CTAs (`--accent`) |
| Accent violet | `#A78BFA` | Highlights / hover (`--accent-glow`) |

CSS variables live in `web/src/styles.css`. Default theme accent is **Onyx violet**; other swatches remain optional in the theme panel.

## Typography

- **Display / brand:** [Sora](https://fonts.google.com/specimen/Sora)
- **UI body:** [IBM Plex Sans](https://fonts.google.com/specimen/IBM+Plex+Sans)

## Pillars (from identity sheet)

1. **Onyx** — strength, precision, and resilience  
2. **Focus** — TIP-first clarity and intent  
3. **Security** — invite-only access and zero trust  
4. **Intelligence** — connections, context, and enrichment  
5. **Action** — from insights to operational impact  
