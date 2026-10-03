#!/usr/bin/env bash
# issue-access.sh — issue a scoped GitHub clone token to a user
#
# Usage:
#   ./tools/issue-access.sh <github-username> [days]
#
# Requires: gh CLI authenticated as the repo owner (0fukuAkz)
#
# What it does:
#   1. Creates a fine-grained PAT scoped only to this repo, read-only, expiring in <days> days
#   2. Prints the clone URL the user should run
#
# Revoking access:
#   Go to https://github.com/settings/tokens and delete the token for that user,
#   OR run:  gh api --method DELETE /user/installations/<id>
#   (easier: just delete it in the GitHub UI under Settings → Developer Settings → Fine-grained tokens)

set -euo pipefail

REPO="0fukuAkz/Evilginx3"
CLONE_URL="https://github.com/${REPO}.git"

USERNAME="${1:-}"
DAYS="${2:-365}"

if [[ -z "$USERNAME" ]]; then
  echo "usage: $0 <github-username> [days]" >&2
  exit 1
fi

if ! command -v gh &>/dev/null; then
  echo "error: gh CLI not found — install from https://cli.github.com" >&2
  exit 1
fi

# Verify the target user exists on GitHub
if ! gh api "users/${USERNAME}" --jq '.login' &>/dev/null; then
  echo "error: GitHub user '${USERNAME}' not found" >&2
  exit 1
fi

echo ""
echo "  Repo    : ${REPO} (private)"
echo "  For user: ${USERNAME}"
echo "  Expires : ${DAYS} days from today"
echo ""

# Fine-grained PATs scoped to a single repo cannot be created via API yet (GitHub limitation).
# The gh CLI surfaces the browser flow — open the URL below and fill in:
#   Token name : access-<username>
#   Expiration : Custom → <DAYS> days
#   Repository access : Only select repositories → ${REPO}
#   Permissions → Repository → Contents : Read-only
#
# Then paste the generated token when prompted.

echo "GitHub's API does not yet support creating fine-grained PATs non-interactively."
echo "Opening the token creation page for you — fill in the fields shown below, then"
echo "paste the token here."
echo ""
echo "  Token name  : access-${USERNAME}"
echo "  Expiration  : Custom, ${DAYS} days"
echo "  Repository  : ${REPO} (Contents: Read-only)"
echo ""

EXPIRES=$(date -d "+${DAYS} days" "+%Y-%m-%d" 2>/dev/null || date -v +${DAYS}d "+%Y-%m-%d")
echo "  Expiry date : ${EXPIRES}"
echo ""

# Open the GitHub fine-grained PAT creation page
gh browse --repo "${REPO}" "https://github.com/settings/personal-access-tokens/new" 2>/dev/null || \
  echo "  → Open manually: https://github.com/settings/personal-access-tokens/new"

echo ""
read -rsp "Paste the generated token (input hidden): " TOKEN
echo ""

if [[ -z "$TOKEN" ]]; then
  echo "error: no token entered" >&2
  exit 1
fi

# Verify the token works against this repo
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token ${TOKEN}" \
  "https://api.github.com/repos/${REPO}")

if [[ "$HTTP_STATUS" != "200" ]]; then
  echo "error: token validation failed (HTTP ${HTTP_STATUS}) — wrong scope or wrong repo?" >&2
  exit 1
fi

echo ""
echo "Token verified."
echo ""
echo "Send the user this clone command:"
echo ""
echo "  git clone https://${TOKEN}@github.com/${REPO}.git"
echo ""
echo "Or using a stored credential:"
echo ""
echo "  git clone https://github.com/${REPO}.git"
echo "  # when prompted: username = ${USERNAME}, password = <token>"
echo ""
echo "The token expires on ${EXPIRES}. To revoke early:"
echo "  https://github.com/settings/tokens"
echo ""
