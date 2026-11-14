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

A snippet with no rule never runs, and a snippet can only be attached to one
rule — so cover both traps in a single expression. In the rule builder:

| Field | Operator | Value |
| --- | --- | --- |
| URI Path | wildcard | `/u/*.json` |

add a second condition (Or) and an extra clause in the expression editor:

```
(http.request.uri.path wildcard "/u/*.json"
 or http.request.uri.path wildcard "/user_avatar/*")
```

Use **URI Path**, not **URI Full**: `full_uri` contains the query string, so a
probe like `/u/foo.json?x=1` would not match.

Restrict to one hostname if the zone carries several:

```
((http.request.uri.path wildcard "/u/*.json"
  or http.request.uri.path wildcard "/user_avatar/*")
 and http.host eq "forum.example.com")
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

## 3. The two traps

**Trap 1 — `/u/<name>.json`.** A request that no real client would make gets a
`200` with a fabricated profile: deterministic id, join date, trust level, post
count, a fake email address carrying the canary, and an `avatar_template`
pointing at your own host.

**Trap 2 — `/user_avatar/…`.** Scanners follow that `avatar_template`, which is
why `/user_avatar/<host>/` shows up in logs after a poisoning campaign. Instead
of a 404 they get a real 96×96 PNG, so the profile keeps looking genuine. The
log entry carries `trap=avatar` instead of `trap=profile`, so you can tell the
two apart in NRQL.

Turn either off with `PROFILE_TRAP` / `AVATAR_TRAP` in `CONFIG`.

## 4. Test

```bash
# trap 1
curl -s -H 'Accept: application/json' https://forum.example.com/u/nosuchuser999.json | head -c 300

# trap 2
curl -s -o /dev/null -D - -H 'Accept: */*' https://forum.example.com/user_avatar/forum.example.com/ | grep -i x-honeypot
```

Expect a JSON profile containing `_hp` from the first, and an `x-honeypot`
header with `content-type: image/png` from the second. Then check a real member's
profile in a browser while logged out — it must load normally, avatars included.

To confirm the origin was not involved, watch your web server's access log while
you run the curls. Nothing should appear.

## 5. Deploying by API

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
  -d '{"rules":[{"expression":"(http.request.uri.path wildcard \"/u/*.json\" or http.request.uri.path wildcard \"/user_avatar/*\")","snippet_name":"u_json_honeypot","description":"honeypot: fake profile JSON and placeholder avatars","enabled":true}]}'
```

**`PUT .../snippet_rules` replaces every snippet rule on the zone.** Read
`GET .../snippet_rules` first and include existing rules, or you will delete
them.

## 6. Rollback

Disable or delete the snippet rule. Traffic returns to the origin immediately.
The snippet code can stay, unused and free.

## What is *not* honeypot material

Not every noisy path deserves a fake response. Two rules of thumb:

- **If your origin answers it, do not fake it.** A `POST /srv/pv` that returns
  `204` from your stack means something real is listening there. Faking the
  response hides a finding; investigate what answered first.
- **If the response has no plausible shape, do not fake it.** A trap works
  because the bot believes it got the real thing. If you cannot produce a
  believable payload, a WAF challenge or rate limit is the honest tool.

## Optional: block or challenge the scanners

The snippet detects; it does not block. Snippets have no persistent state, so
they cannot remember an IP.

A WAF custom rule does block, at the edge, with no origin load:

```
((http.request.uri.path wildcard "/u/*.json"
  or http.request.uri.path wildcard "/user_avatar/*")
 and not cf.client.bot)
```

Action `managed_challenge`. `not cf.client.bot` keeps verified search and AI
crawlers out of it — never challenge those. Prefer `managed_challenge` over
`block`, and watch the rule for a day before tightening.

Trade-off: a challenge tells the bot it was caught, where the honeypot does not.
Running both is reasonable: honeypot for intel, challenge for volume.

## Check your skip rules

If a path you trapped still reaches the origin, look for a WAF **skip** rule
matching it. Security Events records with `"securityAction": "skip"` mean
something in your rule set is bypassing later processing — check which
components that skip covers before assuming the snippet is broken.
