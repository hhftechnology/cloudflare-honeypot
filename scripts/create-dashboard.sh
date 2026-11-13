#!/usr/bin/env bash
#
# Create the "Cloudflare Honeypot" dashboard in New Relic via NerdGraph.
#
#   export NEW_RELIC_ACCOUNT_ID=1234567
#   export NEW_RELIC_USER_KEY=NRAK-...        # a USER key, not a license key
#   bash scripts/create-dashboard.sh
#
# Optional:
#   HONEYPOT_CANARY   your CONFIG.CANARY value (default: honeypot-canary-0001)
#   NERDGRAPH_ENDPOINT  EU accounts: https://api.eu.newrelic.com/graphql
#
# Notes:
#   - The dashboard JSON ships with accountId 0 as a placeholder; this script
#     substitutes your account id everywhere before sending.
#   - NerdGraph creates a NEW dashboard each run. Delete the old one in the UI
#     if you are iterating.
#   - Not tested against every account type; if the mutation fails, the errors
#     array in the response names the offending field.

set -euo pipefail

: "${NEW_RELIC_ACCOUNT_ID:?set NEW_RELIC_ACCOUNT_ID}"
: "${NEW_RELIC_USER_KEY:?set NEW_RELIC_USER_KEY (NRAK-...)}"

CANARY="${HONEYPOT_CANARY:-honeypot-canary-0001}"
NERDGRAPH_ENDPOINT="${NERDGRAPH_ENDPOINT:-https://api.newrelic.com/graphql}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../dashboards/newrelic-honeypot.json"

[ -f "$SRC" ] || { echo "missing $SRC" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# Substitute the account id and the canary string.
payload="$(
  jq --argjson acct "$NEW_RELIC_ACCOUNT_ID" --arg canary "$CANARY" '
    walk(
      if type == "object" and has("accountId") then .accountId = $acct
      elif type == "string" then gsub("honeypot-canary-0001"; $canary)
      else . end
    )
  ' "$SRC"
)"

read -r -d '' MUTATION <<'GQL' || true
mutation CreateHoneypotDashboard($accountId: Int!, $dashboard: DashboardInput!) {
  dashboardCreate(accountId: $accountId, dashboard: $dashboard) {
    entityResult { guid name permalink }
    errors { description type }
  }
}
GQL

body="$(
  jq -n \
    --arg q "$MUTATION" \
    --argjson acct "$NEW_RELIC_ACCOUNT_ID" \
    --argjson dash "$payload" \
    '{query: $q, variables: {accountId: $acct, dashboard: $dash}}'
)"

response="$(
  curl -sS -X POST "$NERDGRAPH_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "API-Key: $NEW_RELIC_USER_KEY" \
    -d "$body"
)"

echo "$response" | jq .

if echo "$response" | jq -e '.data.dashboardCreate.entityResult.guid' >/dev/null 2>&1; then
  echo
  echo "Dashboard created. Open it from Dashboards in New Relic."
else
  echo
  echo "Dashboard was not created - see the errors above." >&2
  exit 1
fi
