# Wire Guard Score into CI and deploys

The point: the score should appear at the **moment code ships**, without anyone remembering to visit a site. Below are paste-in recipes.

## Exit-code contract (`verified-changes check`)

Verified from `src/cli.js`:

| code | meaning |
|---|---|
| `0` | **passed** — verdict SAFE (or within your `--fail-on` threshold) |
| `1` | **findings** — the check found problems (leak / breaks_app / incomplete / untested) |
| `2` | **engine error** — could not run (bad args, project not found, emulator/DB failure) |

`--out-dir <dir>` writes all artifacts at once for CI: `result.json`, `result.md`, `result.sarif`, `dashboard.html`, and `badge.svg`. `--no-log` skips the signed receipt. `--quick` (with a snapshot) re-checks only changed tables.

## GitHub Actions (recommended — full loop)

The published Action posts a PR comment, uploads SARIF to the Security tab, and can open a fix-PR.

```yaml
# .github/workflows/guard-score.yml
name: Guard Score
on: [pull_request, push]
permissions:
  contents: read
  pull-requests: write   # PR comment + fix-PR
  security-events: write # SARIF upload
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Tunceroo/guardscore@v1   # resolves once published to the Marketplace
        with:
          project-dir: .
          fail-on: any          # or: unsafe  (fail only on proven leaks)
          comment: 'true'
          sarif: 'true'
          fix-pr: 'false'       # 'true' to auto-open a PR with proven fixes
          # public-tables: |
          #   products: public catalog, intentionally readable
          # shared-tables: |
          #   org_members: every member of the org may read the roster
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: verified-changes.sarif }
```

Before Marketplace publish, pin by SHA instead: `uses: Tunceroo/guardscore@<sha>`.

## Raw CLI in any CI (no Action)

```bash
npx --yes verified-changes check . --no-log --out-dir ./vc || code=$?
# code: 0 pass · 1 findings · 2 error
cat ./vc/result.md >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || cat ./vc/result.md
[ "${code:-0}" = 2 ] && exit 2   # infra error → fail the job
[ "${code:-0}" = 1 ] && exit 1   # findings → block
```

## Vercel — block a leaking production deploy

Vercel can't run our check as a native "check" without a Git provider, so gate the build with **Ignored Build Step**:

```bash
# vercel project → Settings → Git → Ignored Build Step (or vercel.json "ignoreCommand")
# Exit 0 = SKIP build (we're happy), non-zero = BUILD proceeds.
# We invert: if the check FAILS, we still want to see it — so run it as a build step instead.
```

Cleaner: run it as the **first build step** so a leak fails the deploy:

```json
// package.json
{
  "scripts": {
    "guard": "verified-changes check . --no-log --fail-on unsafe",
    "build": "npm run guard && <your real build>"
  }
}
```

A proven leak → non-zero exit → the Vercel build fails → the deploy is blocked. Use `--fail-on unsafe` so only proven leaks block (not `untested`/`incomplete`, which would be noisy on first adoption).

## Netlify — same idea via build command

```toml
# netlify.toml
[build]
  command = "npx --yes verified-changes check . --no-log --fail-on unsafe && <your build>"
```

## Pre-commit / local gate (optional)

```bash
# .git/hooks/pre-push  (or via husky)
npx --yes verified-changes check . --no-log --fail-on unsafe
```

## The one-liner to put everywhere

```
npx verified-changes check .
```

Cold-start to a Guard Score, no install, no signup. This is the line for the README top, the site, and every launch post.
