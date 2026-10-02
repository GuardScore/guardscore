# Ship it — update GitHub + the website (copy-paste)

Everything below runs on **your** machine (it needs your GitHub, Vercel, and npm accounts — I can't run these from the build sandbox). Two minutes, start to finish.

Repo: **github.com/Tunceroo/guardscore** (already wired into every file).
`DOMAIN` = your new site, once you buy it (e.g. `guardscore.dev`).

---

## 0. Get the code onto your machine

If you're extracting the bundle I sent:

```bash
tar -xzf guard-score-0.18.0.tgz        # creates ./verified-changes
cd verified-changes
npm install
npm test                                # run the FULL suite here (the heavy corpus/live tests need a real machine)
```

If you already have the repo, copy the new/changed files in over your working tree, then `cd` into it.

---

## 1. Update GitHub (one command with the GitHub CLI)

```bash
brew install gh git          # if needed
gh auth login                # GitHub.com → HTTPS → login with a browser

git init -b main
git add -A
git commit -m "Guard Score 0.18.0 — Postgres + Firebase + secrets + Prisma engines, unified output, Apache-2.0, privacy/terms/security"
gh repo create guardscore --public --source=. --remote=origin --push
```

This creates **github.com/Tunceroo/guardscore** and pushes everything. (Use `--private` to stage first; flip to public in Settings later.)

Then on the GitHub repo page: **Settings → General** → confirm the license shows **Apache-2.0**, and **Settings → Security → Security policy** will auto-detect `SECURITY.md`.

Before you make the repo public, do a final secret sweep on your own repo (dogfood it):

```bash
node src/cli.js secrets .
```

---

## 2. Update the website (ideon.market)

The deployable site is the `deploy/` folder (`index.html`, `vercel.json`, `api/badge.js`, `.well-known/security.txt`).

**Easiest — Vercel CLI:**

```bash
npm i -g vercel        # if you don't have it
cd deploy
vercel --prod          # link to the existing "ideon" project when prompted
```

**Or — drag-and-drop:** zip the *contents* of `deploy/` and drop the folder onto https://vercel.com/new (select the `ideon` project). Keep `api/badge.js` inside an `api/` subfolder.

**Best long-term — connect Git once (then it's automatic):**
In the Vercel dashboard → the `ideon` project → **Settings → Git → Connect** your GitHub repo, set **Root Directory = `deploy`**. After that, every `git push` from step 1 auto-deploys the site — no manual deploy ever again. This is the one setup that makes "update GitHub + website" a single action.

Verify after deploy:
```bash
curl -s https://DOMAIN/ | grep -o "leaking user data"          # page is the multi-stack front door
curl -s https://DOMAIN/badge/72.svg | head -c 40                # badge endpoint works
curl -s https://DOMAIN/.well-known/security.txt | head -1        # security.txt is live
```

---

## 3. Publish the CLI + Action (makes `npx verified-changes` and the Action resolve)

```bash
# npm (needs: npm account, then `npm login`)
npm publish --access public

# GitHub Action on the Marketplace:
git tag v0.18.0 && git push origin v0.18.0
# then on GitHub: the repo's Releases → Draft a new release from v0.18.0 →
# check "Publish this Action to the GitHub Marketplace".
```

After `npm publish`, test the promise from a clean directory:
```bash
cd /tmp && npx verified-changes@latest demo
```

---

## 4. Fill the legal/security placeholders first (once)

Before the repo is public, replace the bracketed fields in: `legal/privacy.md`, `legal/terms.md`, `SECURITY.md`, `deploy/.well-known/security.txt`, `LICENSE`/`NOTICE` (copyright name):
- `[LEGAL ENTITY OR YOUR NAME]`, `[CONTACT EMAIL]`, `[SECURITY EMAIL]`, `[WEBSITE URL/DOMAIN]`, `[STATE/COUNTRY]`, `[ORG]/[REPO]`.

Quick find:
```bash
grep -rn "\[LEGAL ENTITY\|\[CONTACT EMAIL\|\[SECURITY EMAIL\|\[WEBSITE\|\[STATE\|\[ORG\]" legal SECURITY.md deploy/.well-known/security.txt
```

---

## Order that avoids dead links

1. Fill placeholders (step 4) → 2. `npm publish` (step 3) so `npx` works → 3. push GitHub public (step 1) → 4. deploy site (step 2) → 5. tag + Marketplace (step 3). Then post the launch.
