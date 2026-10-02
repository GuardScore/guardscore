#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
#  Guard Score — Phase 0, step 2 (optional): publish the CLI to npm.
#
#  This is what makes `npx verified-changes check .` work for anyone.
#  It is NOT required for the GitHub "Add to GitHub" flow — that only needs
#  the repo + v1 tag (ship-github.sh). Do this when you want the direct CLI out.
#
#  Run from inside the project folder:  bash publish-npm.sh
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
die(){ echo "${RED}✗ $*${RST}" >&2; exit 1; }
ok(){ echo "${GRN}✓ $*${RST}"; }

[ -f package.json ] || die "Run this from the project folder (no package.json here)."
NAME="$(node -p "require('./package.json').name")"
VER="$(node -p "require('./package.json').version")"
[ "$NAME" = "verified-changes" ] || die "Unexpected package name '$NAME'."

command -v npm >/dev/null || die "npm not found."
npm whoami >/dev/null 2>&1 || die "Not logged into npm. Run: npm login"
WHO="$(npm whoami)"
ok "npm user: $WHO"

# Is the name available / yours?
if npm view "$NAME" version >/dev/null 2>&1; then
  OWNER_LIST="$(npm owner ls "$NAME" 2>/dev/null || true)"
  if echo "$OWNER_LIST" | grep -q "^$WHO "; then
    ok "You own '$NAME' on npm. Publishing update."
  else
    echo "${YEL}'$NAME' already exists on npm and is owned by:${RST}"
    echo "$OWNER_LIST"
    die "You don't own '$NAME'. Rename the package in package.json (e.g. a scoped @$WHO/guardscore) and re-run."
  fi
else
  ok "'$NAME' is unclaimed — first publish."
fi

# Dry run first so there are no surprises about what ships.
echo "${BLD}→ Files that will be published:${RST}"
npm publish --dry-run 2>&1 | sed 's/^/   /'
echo
read -r -p "Publish $NAME@$VER to npm as $WHO? [y/N] " ans
[ "${ans:-N}" = "y" ] || [ "${ans:-N}" = "Y" ] || die "Aborted."

npm publish --access public
ok "Published $NAME@$VER —  try it:  npx $NAME@latest demo"
