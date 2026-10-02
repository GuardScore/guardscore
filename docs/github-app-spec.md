# Guard Score for GitHub — one-click install (spec)

Goal: a vibecoder clicks **Install**, picks a repo, and Guard Score starts running on
every change — with **zero** terminal, zero file editing, and zero copy-paste.

This spec covers the hosted GitHub App that delivers that. It builds on what already
ships (the composite action in `action.yml` and the paste-in workflow in
`examples/guardscore.yml`); those are the no-server fallback. The App is the layer
that removes the last three clicks.

---

## The three tiers (ship in this order)

| Tier | What the user does | Where the attack runs | Server we run | Status |
|---|---|---|---|---|
| **1 — Paste workflow** | Click button on site → paste file → commit | Their GitHub Actions | none | **shipped** (`/github`) |
| **2 — One-click App** | Click Install → pick repo | Their GitHub Actions | tiny (opens a PR) | this spec |
| **3 — Hosted scan** | Connect Supabase/GitHub, nothing else | **Our** runners | full backend | later, opt-in |

Tiers 1 and 2 keep the core promise intact: **the user's code and schema never touch
our servers.** The App only *writes a workflow file*; the scan still runs inside the
user's own CI. Tier 3 trades that promise for maximum convenience and is strictly
opt-in, clearly labeled.

---

## Tier 2 — the one-click GitHub App

### User flow
1. On the site: **"Add to GitHub"** → **Install Guard Score**.
2. GitHub's native install screen: choose all repos or select repos.
3. On install, our backend receives a webhook and, for each selected repo:
   - creates a branch `guard-score/setup`,
   - adds `.github/workflows/guardscore.yml` (the Tier-1 workflow),
   - opens a pull request titled *"Add Guard Score security checks"* with a plain-English body.
4. The user clicks **Merge**. From then on Guard Score runs on every push/PR.
   - (Optional polish: auto-merge the setup PR when the user granted `contents: write`
     and the repo allows it — but a PR is friendlier and reviewable.)

That's it: **Install → pick repo → Merge.** No terminal, no editor, no paste.

### GitHub App configuration
- **App name:** Guard Score
- **Homepage:** the site (`https://<domain>`)
- **Webhook URL:** `https://<domain>/api/github/webhook`
- **Webhook secret:** random 32+ bytes, stored as env var `GH_WEBHOOK_SECRET`.
- **Permissions (repository):**
  - `Contents: Read & write` — create the branch + workflow file.
  - `Pull requests: Read & write` — open the setup PR; comment results.
  - `Workflows: Read & write` — required to add a file under `.github/workflows/`.
  - `Checks: Read & write` — (optional) surface the score as a Check run.
  - `Metadata: Read` — mandatory baseline.
- **Subscribe to events:** `installation`, `installation_repositories`, `pull_request` (optional, for re-posting on reopen).
- **Where can it be installed:** Any account.

### Backend (small, stateless, serverless)
Runs fine as Vercel serverless functions next to the marketing site. No database
required for Tier 2 (installation tokens are fetched on demand).

Endpoints:
- `POST /api/github/webhook`
  1. Verify `X-Hub-Signature-256` against `GH_WEBHOOK_SECRET` (HMAC-SHA256). Reject otherwise.
  2. On `installation` (action `created`) and `installation_repositories` (action `added`):
     for each new repo, run **setup**.
- **setup(repo, installationId):**
  1. Mint an installation access token:
     - Sign a short-lived App JWT with the App private key (`GH_APP_PRIVATE_KEY`, `GH_APP_ID`).
     - `POST /app/installations/{id}/access_tokens` → installation token (1 hour).
  2. Get the repo's default branch + its head SHA (`GET /repos/{o}/{r}`, `GET /repos/{o}/{r}/git/ref/heads/{branch}`).
  3. Skip if `.github/workflows/guardscore.yml` already exists (`GET /repos/.../contents/...` → 200).
  4. Create branch `guard-score/setup` from head SHA (`POST /git/refs`).
  5. Create the workflow file on that branch (`PUT /repos/.../contents/.github/workflows/guardscore.yml`,
     base64 body = the Tier-1 workflow).
  6. Open the PR (`POST /repos/{o}/{r}/pulls`, base = default branch, head = `guard-score/setup`).

Secrets (env vars): `GH_APP_ID`, `GH_APP_PRIVATE_KEY`, `GH_WEBHOOK_SECRET`, `GH_APP_CLIENT_ID`, `GH_APP_CLIENT_SECRET`.

No user data stored. The only state is what GitHub already holds (the installation).
Nothing about the user's schema, code, or results passes through our server in Tier 2.

### The workflow it installs
Identical to `examples/guardscore.yml` — `uses: <owner>/guardscore@v1`, runs on
push + PR, posts the score, uploads SARIF. The action must be published to the
Marketplace (or referenced by the pinned repo tag) as **`v1`** before the App ships.

---

## Privacy copy (must appear on the install page)
- "Guard Score runs inside **your** GitHub Actions. Your code and schema never reach our servers."
- "The app's only write access is to add one workflow file and comment scores on your PRs."
- Link to the exact permissions and to this spec / the open-source action.

This is a differentiator — say it loudly. Every SaaS scanner ingests your repo; Tier 2 does not.

---

## Tier 3 — hosted scan (later, opt-in only)
For users who won't even merge a PR. They authorize Guard Score to read a repo (or
connect a Supabase project via OAuth); the scan runs on our runners and results show
in a dashboard.
- **Trade-off, stated plainly:** their schema/code is processed on our infrastructure
  for the duration of the scan. Offer ephemeral processing (nothing persisted beyond
  the result), and make Tier 1/2 the recommended default.
- Needs: a job runner (isolated container per scan), OAuth for GitHub/Supabase, a
  results store, and auth. This is the point where Guard Score becomes a hosted product
  with accounts — treat it as the paid tier and gate the roadmap/pricing accordingly.

---

## Prerequisites before Tier 2 can ship
1. Publish the action as `v1` (Marketplace listing or a pinned `v1` tag on the repo).
2. Register the GitHub App; store the four secrets in the site's hosting env.
3. Implement the two webhook branches + `setup()` (~200 lines, one serverless file).
4. Add the **Install Guard Score** button to `/github` (App install URL:
   `https://github.com/apps/<app-slug>/installations/new`).
5. Test on a throwaway repo: install → PR appears → merge → a push triggers a run → score comments.

## Milestones
- **M1 (now, shipped):** Tier 1 paste-in flow at `/github`.
- **M2:** Register the App + webhook, auto-PR on install (Tier 2 core).
- **M3:** Post the Guard Score as a Check run (green/red in the PR checks list) + auto-merge option.
- **M4:** Tier 3 hosted scan as the paid product.
