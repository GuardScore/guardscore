# Launch assets (drafts — you post)

Sequencing: benchmark public → wedge live (`npx` + Action + Marketplace resolve) → detonator study + disclosures done → launch. Do not post before `npx verified-changes check .` works for a stranger, or curious visitors bounce off a dead command. Launch window: HN + Product Hunt Tuesday morning PT; X thread same morning; Reddit that afternoon.

---

## X / Twitter thread (primary)

**1/**
Most apps built with AI in an afternoon are leaking their users' data right now — email, chats, payment info — readable by anyone, no login.

We scanned [N] public AI-built backends. [X]% expose user data to strangers.

Here's the anatomy, and a one-command check 👇

**2/**
The #1 cause isn't exotic. It's this, shipped to prod:

```sql
create policy "enable access for all"
  on public.entries for all
  using (true) with check (true);
```

"Works on my machine" = "works for every stranger on the internet too."

**3/**
The other four patterns we see constantly:
• RLS never turned on
• a bucket named `documents` set `public: true`
• "any signed-in user" mistaken for "the owner"
• test-mode Firestore rules left in

Each is a one-liner to fix. Most builders don't know they're there.

**4/**
So we built Guard Score: paste your schema, get a 0–100 security score in seconds — and it's *proven by attack*, not guessed.

It builds a private copy of your DB and actually tries to break in as a stranger and as another user, then confirms your real users still work.

**5/**
On a blind benchmark of 30 real apps vs 5 other tools, it caught 21/21 real vulns with the fewest false alarms of anything we tested (29/30 correct). Method + corpus are open — re-run it: [link]

**6/**
Check yours in one command, nothing installed, nothing leaves your machine:

```
npx verified-changes check .
```

Or paste your schema at [ideon.market]. Free. Add the badge when you pass.

Don't be in the next [X]%.

---

## Hacker News (Show HN)

**Title:** Show HN: Guard Score – prove whether your AI-built app leaks user data (by attacking a copy)

**Body:**
I kept seeing apps built with AI tools ship with wide-open databases — RLS off, `using (true)` policies, public buckets of private files. So I built a checker that doesn't guess from the rule text: it spins up a private copy of your Postgres from your migrations and actually attacks it as an anonymous visitor and as a second signed-in user, then confirms your legitimate users still work. You get a 0–100 Guard Score and the one-line fix for each hole.

It's a CLI (`npx verified-changes check .`), a GitHub Action (PR comment + SARIF + optional auto fix-PR), an MCP server, and an HTTP API. There's a zero-install web version too.

On a blind benchmark of 30 real public apps against 5 other tools it caught 21/21 real vulns with the fewest false positives (29/30 correct overall). The method, labeled corpus, and scorer are open so you can re-run it — and I'd genuinely like adversarial apps you think it'll get wrong.

Honest limitations: the benchmark is ours until someone independent re-runs it; it's Supabase-only today (Firebase engine is specced, building next); the deep engine needs a local Postgres. Feedback welcome, especially on false positives.

---

## Product Hunt

**Tagline:** A security score for your AI-built app — proven by attack, in one command.

**Description:**
Guard Score tells you, in seconds, exactly what a stranger or another logged-in user can read, change, or delete in your app — and gives you the one-line fix. It doesn't lint your rules; it builds a private copy of your backend and attacks it, then checks your real users still work. Paste your schema on the web, run `npx verified-changes check .`, or drop the GitHub Action in to gate every deploy. Supabase today; Firebase next. Free, open method, badge for your README.

**First comment:** built this after watching too many "launched my app!" posts that were one URL away from dumping every user's email. Blind-benchmarked best of 6 tools; corpus + scorer are open. Tell me what it gets wrong.

---

## Reddit (r/Supabase, adapt for r/Firebase, r/webdev)

**Title:** I built a tool that attacks a copy of your Supabase DB to prove whether RLS actually holds

**Body:**
RLS is easy to get subtly wrong — `using (true)`, RLS left off, "authenticated" mistaken for "owner." Linters guess from the policy text; this builds a private copy from your migrations and actually runs the attack (anon + second user), then confirms your own users still work, so you don't get false lockout noise.

`npx verified-changes check .` — nothing installed, nothing leaves your machine. Also a GitHub Action that comments the result on every PR and can open a fix-PR. Blind benchmark (30 apps, 6 tools): 21/21 caught, 29/30 correct, method open.

Not affiliated with Supabase. Would love migrations you think will fool it.

---

## 60-second demo script (record this — highest-converting asset)

1. (0–8s) Screen: a real-looking vibecoded `schema.sql` open. VO: "This is a journaling app someone built this weekend."
2. (8–20s) Paste into ideon.market → hit Check. Gauge spins to red **35 — Leaking**.
3. (20–38s) Scroll findings: "anyone can read `profiles` (email)", "anyone can write `entries`", "public bucket `documents`". VO reads one.
4. (38–50s) Click "Show the fix" → copy the one-liner → (cut) paste into schema → re-check → gauge to green **100 — Safe**. Copy the badge.
5. (50–60s) VO: "One command. `npx verified-changes check .` Don't ship the leak." End card: Guard Score + URL.

Keep it silent-friendly (captions); most autoplay is muted.
