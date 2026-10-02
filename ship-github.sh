#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
#  Guard Score — Phase 0, step 1: publish the code to GitHub and tag v1.
#
#  This is the CRITICAL step: it makes the GitHub Action (Tunceroo/guardscore@v1)
#  real, which is what the "Add to GitHub" flow on the website depends on.
#
#  Run it from INSIDE the guardscore project folder:
#      bash ship-github.sh
#
#  It is deliberately paranoid — it refuses to run from the wrong folder so the
#  "accidentally committed all of Downloads" incident cannot happen again.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

OWNER="${OWNER:-Tunceroo}"      # override with:  OWNER=youraccount bash ship-github.sh
REPO="guardscore"
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
die(){ echo "${RED}✗ $*${RST}" >&2; exit 1; }
ok(){ echo "${GRN}✓ $*${RST}"; }
info(){ echo "${BLD}→ $*${RST}"; }

# ── 1. Prove we are in the right folder ───────────────────────────────────
HERE="$(pwd -P)"
case "$HERE" in
  "$HOME"|"$HOME/Downloads"|"$HOME/Desktop"|"$HOME/Documents"|/)
    die "You're in $HERE — that's not the project folder. cd into the guardscore folder first." ;;
esac
[ -f package.json ] || die "No package.json here. cd into the guardscore project folder, then re-run."
PKG_NAME="$(node -p "require('./package.json').name" 2>/dev/null || echo '')"
[ "$PKG_NAME" = "verified-changes" ] || die "package.json name is '$PKG_NAME', expected 'verified-changes'. Wrong folder?"
[ -f action.yml ] && [ -d src ] || die "Missing action.yml or src/ — this doesn't look like the guardscore repo."
ok "In the project folder: $HERE"

# ── 2. Tools + auth ───────────────────────────────────────────────────────
command -v git >/dev/null || die "git is not installed."
command -v gh  >/dev/null || die "GitHub CLI (gh) is not installed. Run: brew install gh"
gh auth status >/dev/null 2>&1 || die "You're not logged into gh. Run: gh auth login"
LOGIN="$(gh api user --jq .login 2>/dev/null || echo '?')"
ok "gh authenticated as: ${BLD}$LOGIN${RST}"

# ── 3. Owner sanity (prevents pushing to the wrong account) ───────────────
# OWNER may legitimately differ from your login when it's an ORG you belong to.
if [ "$LOGIN" = "$OWNER" ]; then
  ok "Pushing to your personal account: $OWNER"
elif [ "${FORCE_OWNER:-0}" = "1" ]; then
  ok "FORCE_OWNER set — pushing to $OWNER as $LOGIN."
elif gh api "user/memberships/orgs/$OWNER" >/dev/null 2>&1; then
  ROLE="$(gh api "user/memberships/orgs/$OWNER" --jq .role 2>/dev/null || echo member)"
  ok "Pushing to org ${BLD}$OWNER${RST} as $LOGIN (your role: $ROLE)."
elif gh api "orgs/$OWNER" >/dev/null 2>&1; then
  ok "Org ${BLD}$OWNER${RST} is reachable — proceeding as $LOGIN."
else
  echo
  echo "${YEL}'$OWNER' is neither your login ($LOGIN) nor an org I can confirm you belong to.${RST}"
  echo "If you definitely own/created the '$OWNER' org, bypass this check:"
  echo "    ${BLD}FORCE_OWNER=1 OWNER=$OWNER bash ship-github.sh${RST}"
  echo "Otherwise use your personal account:  OWNER=$LOGIN bash ship-github.sh"
  die "Stopped so you don't push to the wrong account."
fi

# ── 4. Keep the action reference consistent with the owner ────────────────
# The workflow and the website's /github page say `uses: Tunceroo/guardscore@v1`.
# If the owner differs, rewrite those references so the installed workflow resolves.
if [ "$OWNER" != "Tunceroo" ]; then
  info "Rewriting action references Tunceroo/guardscore → $OWNER/guardscore"
  for f in examples/guardscore.yml deploy/github.html deploy/index.html web/frontdoor.html README.md docs/github-app-spec.md; do
    [ -f "$f" ] && sed -i.bak "s#Tunceroo/guardscore#$OWNER/guardscore#g" "$f" && rm -f "$f.bak"
  done
  ok "References updated (remember to redeploy the site so /github matches)."
fi

# ── 5. Clean any leftover git state from a previous botched attempt ───────
if [ -d .git ]; then
  TRACKED="$(git ls-files | wc -l | tr -d ' ')"
  if [ "$TRACKED" -gt 5000 ] || git ls-files | grep -q '^node_modules/\|\.dmg$'; then
    die ".git here looks polluted ($TRACKED tracked files). Run 'rm -rf .git' and re-run this script for a clean start."
  fi
fi
[ -d .git ] || { git init -q; ok "git initialized"; }
git config user.name  >/dev/null 2>&1 || git config user.name  "$OWNER"
git config user.email >/dev/null 2>&1 || git config user.email "$LOGIN@users.noreply.github.com"
git symbolic-ref -q HEAD >/dev/null || git checkout -q -b main 2>/dev/null || true
git branch -M main 2>/dev/null || true

# ── 6. Stage + commit (respecting .gitignore: no node_modules, no tarballs) ─
git add -A
STAGED="$(git diff --cached --name-only | wc -l | tr -d ' ')"
info "Staging $STAGED files (node_modules and tarballs are gitignored)."
git diff --cached --name-only | grep -q '^node_modules/' && die "node_modules is staged — .gitignore didn't apply. Stop."
if git diff --cached --quiet; then
  info "Nothing new to commit."
else
  git commit -q -m "Guard Score v0.18.0 — five engines, GitHub flow, legal, benchmark

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_012AttAVZus6JViwbGxQoaaC"
  ok "Committed."
fi

# ── 7. Ensure the GitHub repo exists and origin points to it ──────────────
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  ok "Repo $OWNER/$REPO already exists."
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$OWNER/$REPO.git"
else
  info "Creating $OWNER/$REPO on GitHub…"
  gh repo create "$OWNER/$REPO" --public \
    --description "Guard Score — attack-based security verifier for AI-built apps. Builds a private copy of your backend, attacks it, and returns a 0–100 score with proven fixes." \
    --source=. --remote=origin
  ok "Repo created."
fi

# ── 8. Push main ──────────────────────────────────────────────────────────
info "Pushing main…"
git push -u origin main
ok "Pushed to https://github.com/$OWNER/$REPO"

# ── 9. Tag v1 (what `uses: OWNER/guardscore@v1` resolves to) ──────────────
if git rev-parse v1 >/dev/null 2>&1; then
  info "Tag v1 already exists locally; moving it to HEAD."
  git tag -f v1
else
  git tag v1
fi
git push -f origin v1
ok "Tagged and pushed ${BLD}v1${RST} — the GitHub Action is now live as $OWNER/guardscore@v1"

echo
echo "${GRN}${BLD}Done.${RST} Next:"
echo "  • The 'Add to GitHub' flow on your site now works end-to-end."
echo "  • Optional: publish the CLI to npm so 'npx verified-changes' works →  bash publish-npm.sh"
echo "  • Set the repo's About/topics/release notes — see docs/github-repo.md"
