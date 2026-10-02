# Guard Score — aspiration → fact: the complete execution plan

The honest bar (your words): better than the alternatives, goes viral, every vibecoder needs it, catches big-tech attention, makes real impact. Today we have a strong prototype with a credible thesis (~6.5/10 against that bar). This is every task that closes the gap, in order, with who does it and how we know it's done.

Legend: **[C]** = Claude can execute in-session · **[U]** = needs you (auth, money, posting, real-world action) · **[C→U]** = Claude produces it, you ship it.

---

## Phase 0 — Stop the bleeding (credibility). Status: DONE this session.

- **[C] ✅ Kill the false "independently benchmarked" claim.** Replaced across the artifact, `deploy/index.html`, and source with precise, defensible copy ("Top score of 6 tools on a blind benchmark"; "reviewers who never saw any tool's output"; "reproduce it yourself"). *Done = no unverifiable superlative on any surface.*
- **[C] ✅ ideon.market integrity.** Confirmed the botched deploy errored and never took the alias; live site intact.

## Phase 1 — Make superiority a fact, not a claim (the benchmark)

The single thing that survives a hostile expert is a benchmark they can re-run and get your number.

- **[C] Publish the benchmark method** (`docs/benchmark.md`): corpus definition, labeling protocol (blind, real Postgres 16, reviewers never saw tool output), the six tools + exact versions/configs, metrics defined, and the leaderboard. *Done = a stranger can read it and know exactly what was measured.*
- **[C→U] Open the corpus + scorer.** The held-out apps, `labels/*.json`, and `score.py` go in a public `benchmark/` dir with a one-command runner (`npm run bench`). *Done = `git clone && npm run bench` reproduces 21/21, 29/30, 1/9.* (U: repo must be public.)
- **[U] Independent replication.** Get ONE credible outsider (a Supabase-adjacent dev, a security researcher) to run it and tweet the number. This is what converts "our benchmark" into "the benchmark." Until then, never say "independent."
- **[C] Expand corpus to ≥100 apps** over time; publish a versioned leaderboard so each release moves a public number. *Done = `benchmark/CHANGELOG` with dated scores.*
- **Risk to state plainly:** competitors will attack corpus selection ("you picked apps you win on"). Mitigate by (a) documenting selection = random public apps, not curated, and (b) inviting adversarial submissions ("send an app you think we'll get wrong").

## Phase 2 — The distribution wedge (every vibecoder needs it → every vibecoder *uses* it)

A destination site is the weakest distribution for a tool whose users don't know they need it. Win the **moment of deploy**, where the score appears without being sought.

- **[C] ✅ GitHub Action exists** (`action.yml`): PR comment, SARIF upload, `fail-on`, auto fix-PR, verdict output. Strong already.
- **[C] Harden the CLI for CI** (`src/cli.js check`): stable exit codes (0 safe / 1 findings / 2 error), `--out-dir` with `result.json|md|sarif`, `--format`. Verify + document each. *Done = documented exit-code contract + a copy-paste workflow YAML.*
- **[C] Vercel/Netlify deploy-check recipe** (`docs/integrations/`): a pre-deploy check (Vercel Ignored Build Step / GitHub check that gates the Vercel deployment; Netlify build plugin). *Done = paste-in config that blocks a leaking deploy.*
- **[C] `npx verified-changes check` quickstart** front and center in README + site. Zero-install first run. *Done = one command from cold to a Guard Score.*
- **[C→U] Publish to npm** (`npm publish`) so `npx verified-changes` resolves, and to **GitHub Marketplace** so `uses: verified-changes/action@v1` resolves. (U: npm auth + a tagged release + public repo.) *Done = both resolve for a stranger.*
- **[C→U] Bolt / Lovable / v0 / Replit integration** — the highest-leverage wedge. These are where vibecoded backends are born. Options, easiest first: (1) a shareable "add this check" template repo; (2) a one-click GitHub Action install; (3) direct partnership so the score shows in-product. (U: outreach.) *Done = at least one AI-builder path where the score appears automatically.*
- **[C] MCP server polish** so the score is available inside Cursor/Claude/Windsurf during the build, not only after. *Done = `verified-changes-mcp` documented + a 3-line install for each host.*

## Phase 3 — The detonator (the thing that actually goes viral)

Scanners don't spread; results do. You need ONE public proof that indicts the ecosystem — without naming victims (your standing constraint).

- **[C] Design the ecosystem study** (`docs/ecosystem-study.md`): methodology to measure "what fraction of AI-built apps leak user data," using only lawfully obtainable public artifacts (public GitHub repos with `supabase/migrations`, public templates), aggregate-only reporting, zero victim names. *Done = a protocol a lawyer and a security researcher both nod at.*
- **[C] Build the study harness**: run the static engine (and, where a schema is public, the full engine) across N public repos, output aggregate stats + anonymized exemplar patterns. *Done = `npm run study -- <repo-list>` → aggregate JSON.*
- **[U] Responsible disclosure first.** Any app found leaking real user data gets a private, dated disclosure + grace period BEFORE any publication. This is non-negotiable — it's also what earns security-community respect instead of a pile-on. (U: you send disclosures.)
- **[C→U] The tweetable artifact**: "We scanned N public AI-built backends. X% expose user data anyone can read. Here's the anatomy (no apps named), and a one-command check so yours isn't next." A single chart + the anatomy + the CTA. (U: you post.) *Done = a shareable page/thread that stands on its own.*
- **The leader-attention mechanic:** the stat implicates a platform's ecosystem (Supabase/Firebase/Bolt). Those founders engage with ecosystem-health data far more than with tools. Tag responsibly, lead with the fix, not the shame.

## Phase 4 — Launch (turn the detonator into a wave)

- **[C→U] Launch assets** (`docs/launch/`): X thread, Show HN, Product Hunt, r/Supabase + r/Firebase posts, a 60-sec demo script. Honest, hook-first. (U: post them.) *Done = drafts ready to paste.*
- **[C→U] The 60-second demo GIF/video**: paste a real vibecoded schema → red "Leaking" → the exact fix → green + badge. This is the single most persuasive asset. (U: record, or I script it for a screen-capture tool.) *Done = a loopable clip.*
- **[U] Seed the badge loop**: put the Guard Score badge on your own repos/apps first; every badge is an ad that recruits the next builder.
- **[U] Sequencing**: benchmark public → wedge live (npm+Action+Marketplace) → detonator study + disclosures done → launch week (HN Tue, PH same day, X thread, Reddit). Never launch before the wedge resolves, or curious people bounce off a dead `npx`.

## Phase 5 — Moat & durability (so it's not commoditized in a quarter)

- **[C] Lean the position to "one Guard Score for any backend."** A single platform (Supabase) can safe-default its own RLS and erase your Supabase-only edge; the cross-stack, attack-proof standard is what they can't copy. Ship Firebase engine (spec done: `docs/firebase-engine.md`) to prove "any stack."
- **[C] The `proof` receipt** on every finding (literal request→response). Reproducibility is the credibility multiplier and the anti-FUD defense. Backport to Supabase.
- **[C] Guard Score as a spec** (`docs/guard-score-spec.md`): publish the 0–100 rubric and caps as an open standard others can implement/cite. A standard outlives a tool.
- **[U] Decide the business model** now so engineering serves it: free CLI/Action (adoption) + paid org dashboard / continuous monitoring / compliance report (revenue). Don't monetize the wedge; monetize the team layer.

---

## The exhaustive checklist (every last thing), by owner

**Claude, this session or next (no external deps):**
1. ✅ Remove false credibility copy (done).
2. `docs/benchmark.md` — open method + leaderboard.
3. `docs/ecosystem-study.md` — study protocol + disclosure rules.
4. Study harness script (`study/run.mjs`) — aggregate-only.
5. `docs/launch/*` — X thread, Show HN, PH, Reddit, demo script.
6. CLI exit-code contract doc + copy-paste CI YAML (`docs/integrations/github.md`).
7. Vercel/Netlify deploy-check recipes (`docs/integrations/vercel.md`, `netlify.md`).
8. README quickstart rewrite (npx one-liner first).
9. `docs/guard-score-spec.md` — the open scoring standard.
10. Firebase engine build (Milestone 1) — per `docs/firebase-engine.md`.
11. `proof` receipts on findings (Supabase engine).

**Claude produces → you ship (needs your auth/accounts):**
12. Make the repo public. (U)
13. `npm publish` + tagged release. (U, after 12)
14. GitHub Marketplace listing for the Action. (U, after 12)
15. Deploy multi-stack front door to ideon.market via git-connect. (U — files already delivered)
16. Record the 60-sec demo clip from my script. (U)

**Only you (judgment/relationships/real-world):**
17. One independent replication of the benchmark. (U)
18. Ecosystem-scan disclosures to affected apps + grace period. (U)
19. AI-builder partnership outreach (Bolt/Lovable/v0/Replit). (U)
20. Post the launch, tag platform founders responsibly. (U)
21. Pick the business model + pricing. (U)

---

## Honest scorecard delta

| Criterion | Today | After this plan executes |
|---|---|---|
| Superior to alternatives | self-benchmarked only | reproducible + independently replicated |
| Goes viral | mechanic exists, no fuel | detonator study + demo + badge loop |
| Every vibecoder needs/uses it | destination site only | deploy-time wedge + AI-builder path |
| Big-tech attention | none | ecosystem stat implicating a platform |
| Real impact | zero adoption | measured installs + disclosed-and-fixed apps |

The gap was never engine quality. It's distribution, an unimpeachable benchmark, and one detonating public result. Everything above serves those three.
