# GitHub repo setup — paste-ready (Tunceroo/guardscore)

After `gh repo create guardscore --public --source=. --remote=origin --push`, set these on the repo page so it looks finished.

## About (repo sidebar → ⚙️ Edit)

**Description:**
> Guard Score — attack-based security verifier for AI-built apps. Builds a private copy of your backend, attacks it as a stranger and as another user, and returns a 0–100 score with proven fixes. Supabase · Postgres · Firebase · leaked-secret scanning.

**Website:** your domain once live (e.g. `https://guardscore.dev`)

**Topics** (add all):
```
security  guard-score  supabase  postgres  row-level-security  rls  firebase  firestore  prisma
secrets-scanning  vibecoding  ai-generated-code  appsec  devsecops  sast  cli  github-action  mcp
```

## Repo settings worth flipping

- **Settings → General → Features:** enable Issues and Discussions (community for a launch).
- **Settings → Security → Security policy:** GitHub auto-detects `SECURITY.md` — confirm the green check.
- **License:** GitHub auto-detects `LICENSE` (Apache-2.0) and shows it in the sidebar.
- **Social preview:** Settings → General → Social preview — upload a 1280×640 card (the badge + "Is your app leaking user data?" reads well). Optional but high-leverage for shares.

## Release notes — v0.18.0 (Releases → Draft a new release → tag v0.18.0)

**Title:** `v0.18.0 — five engines, one Guard Score`

**Body:**
```markdown
Guard Score verifies AI-built app backends the honest way: it builds a private copy, **attacks it**, and proves each hole with a receipt — then confirms your real users still work.

### Engines
- **Supabase** (Postgres + RLS + Storage) — full attack engine; benchmarked best of 6 tools on 30 blind-reviewed real apps (21/21 caught, 29/30 correct, fewest false alarms).
- **Postgres (generic)** — any host with `current_setting`-based RLS (PostgREST, hand-rolled, Prisma-with-RLS); attacked as a non-owner role.
- **Firebase** (Firestore + Storage) — attack engine in the emulator: open rules, cross-user, `get()/exists()` bypass, collection-group leaks, field tamper, storage. Run with `npm run firebase:check`.
- **Leaked secrets** — scans source/config for service_role/Stripe/AWS/GCP/private keys and committed `.env`; never flags public keys.
- **Prisma** — review-tier advisor (Prisma authz is app-layer), honestly scoped.

### Everything else
- One 0–100 **Guard Score**, a **proof receipt** on every finding, and a labeled fix (proven-on-copy vs advisory).
- Ships as a **CLI, GitHub Action, MCP server, and HTTP API**, plus a zero-install **web front door** and a shareable **badge**.
- `watch` mode for continuous drift monitoring; unified output across every engine.
- Now **Apache-2.0** licensed.

### Try it in 10 seconds
```bash
npx verified-changes demo      # watch it break a leaky app
npx verified-changes check .   # scan your own
```
```

## Pin note

Consider pinning an Issue titled "Send an app you think Guard Score will get wrong" — adversarial submissions are the fastest way to make the benchmark unimpeachable, and it signals confidence.
