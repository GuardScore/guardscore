# The detonator: "How much of the AI-built web leaks user data" — study protocol

Goal: one public, defensible result that indicts the *ecosystem* (not any app) and makes the fix obvious — the thing that actually spreads and earns platform-founder attention. Scanners don't go viral; a number like "X% of AI-built backends expose user data to anyone" does.

**Hard constraints (non-negotiable):**
1. **Never name or publish a specific vulnerable app.** Aggregate stats and anonymized *patterns* only.
2. **Only lawfully, publicly obtainable artifacts.** Public GitHub repos containing `supabase/migrations/*.sql` or `firestore.rules`, public starter templates, public gists. No scraping behind auth, no probing live production databases, no attempts against anyone's running backend.
3. **Static analysis only for the study.** The full attack engine runs against a *private copy built from public migration files*, never against a live third-party system.
4. **Responsible disclosure precedes publication** for anything that maps to a real, live, exploitable deployment (see §5).
5. Run everything only on the project's own dedicated infra — never RentAnAgent/humara or any unrelated system.

## 1. Sample frame

- **Source:** GitHub code search for public repos containing `supabase/migrations/` SQL and/or `firestore.rules`, filtered to repos that look like real apps (has a frontend, recent commits) vs. tutorials/forks. De-dupe by content hash so template clones don't inflate the number.
- **Size:** target N ≥ 500 for a headline stat; report exact N and the date. Bigger N = harder to dismiss.
- **Stratify:** by stack (Supabase/Firebase), and if detectable, by "built with an AI builder" signal (Bolt/Lovable/v0/Replit markers in README or config) so you can say "AI-built specifically."

## 2. What we measure (all aggregate)

- % with at least one **critical** leak (anon read/write of personal-data tables; `allow read, write: if true`; test-mode rules).
- % exposing specific data classes (email, tokens, payment identifiers) to anonymous readers.
- Distribution of Guard Scores across the sample (a histogram is the tweet image).
- The **top 5 anatomy patterns** — e.g. "RLS never enabled," "`for all using (true)`," "public bucket named `documents`" — as *categories*, with a synthetic (invented) example for each, never a real one.

## 3. Harness (built — two commands)

```
study/collect.mjs   ├─ GitHub code search (PUBLIC repos only) for supabase/migrations/*.sql + firestore.rules
                    ├─ downloads ONLY those files via the API (never clones, never touches a live app/key)
                    ├─ opaque sha256 id per repo; writes study/input/<id>/… + private study/input/_manifest.json
study/run.mjs       ├─ scan: web/scan.js (Supabase) / web/firebase-scan.js (Firebase) per source
                    ├─ aggregate: counts, score histogram, pattern frequencies — NO identifiers in output
                    └─ emit: study/out/aggregate.json  (+ study/out/private-index.json with --private-index)
```

Run it:
```bash
# 1. collect a public corpus (needs a read-only GitHub PAT; study/input/ is gitignored)
GITHUB_TOKEN=ghp_xxx node study/collect.mjs --max 300 --stack both
# 2. produce the aggregate + the private disclosure index
node study/run.mjs study/input --private-index
# → study/out/aggregate.json is the publishable number; private-index.json is disclosure-only, never published
```

`collect.mjs` reads **public source code through the GitHub API** — it never connects to, authenticates against, or probes anyone's live backend; the only "attack" is the static scanners (and, optionally, the engine against a private copy built from the public files on our own infra). Output contains **no repo names, URLs, authors, or any field that re-identifies a source.** The private repo→finding mapping exists *only* to drive disclosure (§5) and is never published.

## 4. The publishable artifact

A single page/thread:
- **Headline stat + histogram** ("N public AI-built backends scanned. X% expose user data anyone can read. Median Guard Score: Y.").
- **The anatomy** — the 5 patterns with synthetic examples and the one-line fix for each.
- **The CTA** — `npx verified-changes check .` and the badge. "Don't be in the next X%."
- **The method link** — this doc + the open scorer, so it survives scrutiny.
- Tone: ecosystem health and the fix, not shaming. That framing is what gets a Supabase/Firebase/Bolt founder to engage instead of defend.

## 5. Responsible disclosure (do this BEFORE publishing)

- For any sampled repo whose finding maps to a **live, exploitable** deployment, send a private disclosure to the maintainer (GitHub security advisory / email) with the specific finding and fix, dated, before any publication.
- Give a grace window (e.g. 30–90 days) before the aggregate study goes out; the study still names no one, but disclosure first is what earns security-community respect rather than a backlash.
- Publish a short disclosure policy alongside the study so the process is transparent.
- If a maintainer asks to be excluded from even the aggregate, honor it.

## 6. Why this converts

- **Viral:** a scary, specific, verifiable number with a one-command fix is inherently shareable.
- **Leader attention:** the stat is about a platform's ecosystem; founders track ecosystem-health data closely. Lead with "here's the fix we're shipping to your users," not "your platform is insecure."
- **Impact:** every disclosure is a real app fixed; every install from the CTA is a future leak prevented — both are measurable and both are the story for the *next* post.

## 7. Legal/ethical sign-off checklist (you confirm before running)

- [ ] Only public artifacts fetched; no auth bypass, no live-DB probing.
- [ ] Deep engine runs only on private copies built from public files, on our infra.
- [ ] Output re-identifies no one; source mapping kept private, used only for disclosure.
- [ ] Disclosure sent + grace period elapsed for any live-exploitable finding.
- [ ] Disclosure policy published; opt-outs honored.
