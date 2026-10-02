# Launch readiness — go/no-go checklist

Everything an outsider touches, and whether it's ready. **[C]** was done in-session; **[U]** needs you.

## Ready now (done)

- **[C] Product reads as one tool.** Five engines (Supabase, Postgres, Firebase, secrets, Prisma) speak one voice via `src/render.js`: same Guard Score header, findings, proof receipts, fixes; `--format json` everywhere.
- **[C] One-command entry.** `npx verified-changes check .` auto-detects the stack. Exit codes 0/1/2 documented.
- **[C] README is multi-stack and honest.** Leads with the one-liner; "What it checks" table with per-stack tier (proven-by-attack vs advisory); scope stated plainly.
- **[C] Front door live** (artifact v7): accurate stack breadth, honest benchmark copy, Guard Score badge loop.
- **[C] Trust guardrails.** Secret scanner ignores placeholders/`.env.example`; fix certainty labeled (`docs/fixes-status.md`); benchmark method open (`docs/benchmark.md`).
- **[C] Fast test suite green** (12 suites) + `api` + `mcp` verified.

## Hard blockers before you can publish — [U], and one is a real gotcha

1. **`package.json` will refuse to publish as-is.** It has `"private": true` and `"license": "UNLICENSED"`.
   - `private: true` **blocks `npm publish` entirely** — npm will error. Remove it to publish.
   - `UNLICENSED` + a public repo confuses every visitor and blocks contribution. **You must choose a license.** This is a business decision I won't make for you:
     - **MIT / Apache-2.0** — maximal adoption (best for the viral/distribution goal), anyone can use/fork.
     - **Business Source License (BSL) / Fair-source** — source-visible, converts to open later, blocks a competitor from reselling it.
     - **Proprietary / closed** — keep the repo private, distribute only the built CLI.
   Tell me which and I'll set `license`, remove `private`, add the `LICENSE` file, and align the front-door/README footers.

2. **Run the full suite on a real machine.** The heavy `corpus` and `live` suites can't finish in the build sandbox (time/network). `npm test` from a full checkout is the final green light.

3. **Publish + deploy so the links work** (in this order, or launch links are dead):
   - `npm publish` (after #1) → `npx verified-changes` resolves for strangers.
   - GitHub Marketplace listing for the Action → `uses: <you>/verified-changes/action@v1` resolves.
   - Deploy the multi-stack front door to **ideon.market** (files delivered; `vercel.json` fixed).

## Should-do before the launch post

- **[U] One independent benchmark replication.** Someone credible runs `npm run bench` and posts the number. This is what turns "our benchmark" into a fact you can claim without the word "our".
- **[U] Record the 60-sec demo** from `docs/launch/launch-assets.md` (paste schema → red → fix → green + badge).
- **[U] Run the ecosystem study + disclosures** (`docs/ecosystem-study.md`) — the detonator. Disclosures first, aggregate-only publication after the grace window.

## Launch sequence (once blockers clear)

benchmark reproducible → npm + Action + Marketplace resolve → ideon.market live → demo recorded → study + disclosures done → **launch day**: HN (Show HN) + Product Hunt Tue AM PT, X thread same morning, Reddit that afternoon. Copy is ready in `docs/launch/launch-assets.md`.

## The one-line status

Engineering is launch-ready and reads as one best-in-class product. The gate is now entirely yours: **pick a license + remove `private`, run `npm test` once on a real machine, publish + deploy, get one independent benchmark run.** None of it is more building — it's the distribution that turns a lab-fact into a world-fact.
