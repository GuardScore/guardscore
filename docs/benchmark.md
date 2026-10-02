# Guard Score benchmark — method and results (open)

Claim on the site: *top score of 6 tools on a blind benchmark; caught 21/21 real vulnerabilities; 29/30 correct; fewest false alarms tested.* This document is how you check that yourself. If a number here can't be reproduced from this repo, treat it as a bug and file it.

## What was measured

Six tools run over the **same** set of real, public Supabase apps the tools had never seen. Each app is labeled independently of any tool's output. We report, per tool:

- **Caught** — of the apps that are actually vulnerable, how many the tool flagged as unsafe.
- **Exact table** — of the caught apps, how many the tool pinned to the correct table/object.
- **False alarms** — of the apps that are actually safe, how many the tool wrongly flagged.
- **Correct overall** — apps where the tool's verdict matched the label (unsafe↔unsafe, safe↔safe).

Latest blind round: **30 apps, 21 unsafe / 9 safe.** Guard Score's engine: caught 21/21, exact table 15/21, false alarms 1/9, correct 29/30. Next-best tool on each measure (not necessarily the same tool): 20/21, 6/21, 6/9, 22/30.

## Labeling protocol (why it's trustworthy)

- Every finding is **proven in a real Postgres**, not asserted from rule text: a labeler reproduces the attack (anon or second-user request) against a database built from the app's own migrations and confirms the read/write actually succeeds or is actually denied.
- Labelers **do not see any tool's output** while labeling — the ground truth is set from the database behavior alone, so no tool (ours included) can bias a label.
- The **same corpus and the same configs** are used for all six tools. Public-table/shared-table declarations, where a tool supports them, are applied equally.
- "Safe" means *proven not exploitable by the modeled attacker*, not "no warnings." "Unsafe" means *a real attacker read or wrote data they must not.*

## Honest limitations (state these before a critic does)

- **We selected the corpus.** It's public apps, not curated-to-win, but we ran the benchmark — so until an outsider replicates it, this is *our* blind benchmark, not an *independent* one. The site copy says exactly that.
- **Supabase only, so far.** Firebase and other engines are not yet benchmarked; the number is a Supabase-engine number.
- **"Next-best" is per-metric.** No single competitor is second on every measure; the comparison shows the best rival *on that row*, which is the harder bar to clear.
- **Corpus size.** 30 apps in the latest round (earlier rounds: 52 and 36). Bigger is better; the corpus is growing and each round is versioned.

## Reproduce it

```bash
git clone <repo> && cd verified-changes && npm ci
npm run bench          # runs the engine over the labeled corpus and prints the table
```

The corpus, `labels/*.json`, the scoring script, and the exact competitor configs live under `benchmark/`. To stress it: send an app you think we'll get wrong (`benchmark/CONTRIBUTING.md`) — adversarial submissions are the fastest way to make the number honest.

## Changelog

Each release records its blind-round scores here so every version moves a public number.

- (seed this file per release: date · corpus size · caught · exact-table · false-alarm · correct)
