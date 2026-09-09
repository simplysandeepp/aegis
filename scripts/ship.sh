#!/usr/bin/env bash
# Ship one batch of files as its own pull request:
#   branch -> add -> commit -> push -> open PR -> squash-merge -> delete branch
#
#   ./scripts/ship.sh <branch-slug> "<title>" "<body>" file1 file2 ...
#
# One merged PR per batch keeps the history bisectable and readable.
set -euo pipefail

SLUG="$1"; TITLE="$2"; BODY="$3"; shift 3

git checkout -q main
git pull -q --ff-only origin main 2>/dev/null || true
git checkout -q -B "$SLUG"

git add -- "$@"
if git diff --cached --quiet; then
  echo "ship: nothing staged for $SLUG, skipping"
  git checkout -q main
  exit 0
fi

git commit -q -m "$TITLE" -m "$BODY"
git push -q -u origin "$SLUG"

PR_URL=$(gh pr create --base main --head "$SLUG" --title "$TITLE" --body "$BODY")
echo "ship: opened $PR_URL"

gh pr merge "$SLUG" --squash --delete-branch --admin >/dev/null 2>&1 \
  || gh pr merge "$SLUG" --squash --delete-branch >/dev/null

git checkout -q main
git pull -q --ff-only origin main
git branch -q -D "$SLUG" 2>/dev/null || true
echo "ship: merged + deleted $SLUG"
