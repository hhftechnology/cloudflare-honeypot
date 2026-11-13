# Deploying on Cloudflare

## Prerequisites

- The hostname is proxied through Cloudflare (orange cloud). Snippets do not run
  on DNS-only records.
- Snippets are available on your plan. Cloudflare's docs currently list them as
  unavailable on Free (Pro: 25, Business: 50, Enterprise: 300). Some legacy
  zones still show 5 slots.

## 1. Create the snippet

Rules → **Snippets** → **Create Snippet**.

- Name: `u_json_honeypot` — lowercase letters, digits and `_` only, and it
  cannot be renamed later.
- Paste `snippet/honeypot.js`.
- Edit `CONFIG`: at minimum `CANARY`, then `NEW_RELIC_LICENSE_KEY` or `LOG_URL`.

## 2. Attach the snippet rule

A snippet with no rule never runs. In the rule builder:

| Field | Operator | Value |
| --- | --- | --- |
| URI Path | wildcard | `/u/*.json` |

Preview:

```
(http.request.uri.path wildcard "/u/*.json")
```

Use **URI Path**, not **URI Full**: `full_uri` contains the query string, so a
probe like `/u/foo.json?x=1` would not match.

Restrict to one hostname if the zone carries several:

```
(http.request.uri.path wildcard "/u/*.json" and http.host eq "forum.example.com")
```

### Why not a regex

The `matches` operator needs a Business plan or WAF Advanced. On Pro or Free the
dashboard rejects the rule with:

```
not entitled: the use of operator Matches is not allowed
```

`wildcard` is broader — it can also match `/u/name/summary.json` — but the
snippet re-checks the path itself and passes anything that is not exactly
`/u/<one segment>.json` to the origin, so nothing legitimate is affected.

## 3. Test

```bash
curl -s https://forum.example.com/u/nosuchuser999.json | head -c 300
```

Expect a JSON profile containing `_hp`. Then check a real member's profile in a
browser while logged out — it must load normally.

To confirm the origin was not involved, watch your web server's access log while
you run the curl. Nothing should appear.

## 4. Deploying by API

Token permission: **Zone → Snippets → Edit**. Keep the token in the environment.

```bash
export ZONE_ID=<32 hex chars>
export CLOUDFLARE_API_TOKEN=<token>

curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/snippets/u_json_honeypot" \
  -X PUT \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  --form "files=@snippet/honeypot.js" \
  --form 'metadata={"main_module":"honeypot.js"}'

curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/snippets/snippet_rules" \
  -X PUT \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"expression":"(http.request.uri.path wildcard \"/u/*.json\")","snippet_name":"u_json_honeypot","description":"honeypot: fake 200 for /u/*.json enumeration","enabled":true}]}'
```

**`PUT .../snippet_rules` replaces every snippet rule on the zone.** Read
`GET .../snippet_rules` first and include existing rules, or you will delete
them.

## 5. Rollback

Disable or delete the snippet rule. Traffic returns to the origin immediately.
The snippet code can stay, unused and free.

## Optional: block or challenge the scanners

The snippet detects; it does not block. Snippets have no persistent state, so
they cannot remember an IP.

A WAF custom rule does block, at the edge, with no origin load:

```
(http.request.uri.path wildcard "/u/*.json" and not cf.client.bot)
```

Action `managed_challenge`. `not cf.client.bot` keeps verified search and AI
crawlers out of it — never challenge those. Prefer `managed_challenge` over
`block`, and watch the rule for a day before tightening.

Trade-off: a challenge tells the bot it was caught, where the honeypot does not.
Running both is reasonable: honeypot for intel, challenge for volume.
