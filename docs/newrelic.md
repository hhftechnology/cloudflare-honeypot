# New Relic: logs, dashboard, alerts

The snippet posts one log entry per hit to the New Relic Log API. One subrequest,
no agent, nothing installed on your server.

## 1. License key

New Relic → account menu → **API keys** → **Ingest – license**. Copy the license
key (region-prefixed on EU accounts, e.g. `eu01xx…`).

Not the `NRAK-` user key, and not a browser key — those return 403 from the Log
API and nothing appears. License keys are ingest-only: they can write data and
cannot read or query it, which is why keeping one inside the snippet is
tolerable.

## 2. Endpoint by region

| Region | Endpoint |
| --- | --- |
| US (default) | `https://log-api.newrelic.com/log/v1` |
| EU | `https://log-api.eu.newrelic.com/log/v1` |
| Japan | `https://log-api.jp.nr-data.net/log/v1` |

Wrong region is the most common reason for silence.

## 3. What arrives

`message` is one readable line:

```
honeypot hit forum.example.com/u/oznuruzal.json | ip 82.108.93.175 |
asn 2856 BT Public Internet Service | GB / London | Mozilla/5.0 (X11; Linux
x86_64) AppleWebKit/537.36 … Chrome/144.0.0.0 Safari/537.36
```

The same data is attached as attributes:

| Group | Attributes |
| --- | --- |
| what was probed | `host`, `path`, `username`, `query`, `method` |
| who | `ip`, `asn`, `as_org`, `country`, `region`, `city`, `colo` |
| connection | `http_protocol`, `tls_version` |
| client | `ua`, `accept`, `accept_language`, `referer` |
| trap marker | `event` (`honeypot_hit`), `canary` |

Attributes are what NRQL filters, facets and alerts on.

See `examples/sample-log.json` for the exact payload.

## 4. Queries

Run these in **Query your data** (the full NRQL editor), not the Logs search box
— that one is fussy about `SINCE` and has its own time picker.

```sql
-- everything, newest first
SELECT * FROM Log WHERE canary = 'honeypot-canary-0001' SINCE 1 day ago

-- volume
SELECT count(*) FROM Log WHERE canary = 'honeypot-canary-0001' SINCE 1 day ago

-- who and from where
SELECT count(*) FROM Log WHERE canary = 'honeypot-canary-0001'
FACET ip, as_org, country SINCE 7 days ago LIMIT 50

-- what they are hunting
SELECT count(*) FROM Log WHERE canary = 'honeypot-canary-0001'
FACET username SINCE 7 days ago LIMIT 50

-- sanity check: anything that looks like a real browser?
SELECT count(*) FROM Log WHERE canary = 'honeypot-canary-0001'
FACET ua, as_org SINCE 7 days ago
```

Filter on `canary`, not `event` — the canary value is unique to your trap and
cannot collide with anything else in the account.

## 5. Dashboard

`dashboards/newrelic-honeypot.json` is an eleven-widget dashboard in New Relic's
import format. It ships with two placeholders that **must** be replaced with your
own values. Miss either and you either get an import error or a dashboard that
shows zeros forever.

| Placeholder | Replace with | Where it appears |
| --- | --- | --- |
| `"accountId": 0` | your New Relic account id | 11 query objects |
| `honeypot-canary-0001` | your `CONFIG.CANARY` from the snippet | 11 query filters |

### Find your account id

Any of these:

- The **account switcher** at the bottom-left of New Relic lists the id next to
  the account name.
- The URL of almost any page: `one.newrelic.com/accounts/<id>/…`.
- **Query your data** → the account picker shows it.
- An existing dashboard → `...` → **Download dashboard** → JSON → `accountId`.

### Option A — the script (recommended, no editing)

```bash
export NEW_RELIC_ACCOUNT_ID=1234567
export NEW_RELIC_USER_KEY=NRAK-...          # a USER key, not a license key
export HONEYPOT_CANARY=hhf-honeypot-7f21   # your CONFIG.CANARY
bash scripts/create-dashboard.sh
```

It rewrites both placeholders and calls NerdGraph `dashboardCreate`. EU accounts:
also export `NERDGRAPH_ENDPOINT=https://api.eu.newrelic.com/graphql`. Each run
creates a new dashboard, so delete the previous one while iterating.

### Option B — the UI import, after editing the JSON

```bash
# macOS / Linux
sed -i -e 's/"accountId": 0/"accountId": 1234567/g' \
       -e 's/honeypot-canary-0001/hhf-honeypot-7f21/g' \
       dashboards/newrelic-honeypot.json
```

```powershell
# Windows PowerShell
(Get-Content dashboards/newrelic-honeypot.json) `
  -replace '"accountId": 0', '"accountId": 1234567' `
  -replace 'honeypot-canary-0001', 'hhf-honeypot-7f21' |
  Set-Content dashboards/newrelic-honeypot.fixed.json
```

Then: **Dashboards → Import dashboard → paste → Permissions "Edit – everyone in
account" → Import.**

### After it imports

- Set the time range to **7 days** (top right). The default is often 30 minutes,
  which makes a working dashboard look empty.
- If the widgets show numbers but the charts look sparse, that is just log
  volume — a few hundred probes a day is normal.

### If the import fails

`Failed to create dashboard` with a **Schema** tag is validation, not a data
problem. In order of likelihood:

1. **`accountId: 0` left in place.** Zero is not an account; the import validates
   it before creating anything. Replace all eleven.
2. **Layout outside the grid.** New Relic's dashboard grid is 12 columns wide and
   a widget's `column + width - 1` may not exceed 12. If you hand-edited the
   layout, check it.
3. **Wrong JSON shape.** The importer expects a dashboard export, not a widget or
   a NerdGraph mutation payload. The top level must be
   `{name, permissions, pages:[{widgets:[…]}]}`.

To bisect: import a one-widget dashboard with a `viz.markdown` widget and no
queries at all. If that succeeds, the wrapper is fine and the problem is in the
query objects (i.e. `accountId`). If it fails, the wrapper is wrong — compare
against `Download dashboard` from any existing dashboard in your account.

Fallback that cannot fail: **Query your data** → run
`SELECT count(*) FROM Log WHERE canary = '<your canary>' TIMESERIES` → **Add to
dashboard**. Repeat per widget. Slower, but it builds against the live schema.

Eleven widgets: total hits, unique IPs, usernames probed, countries, hits over
time, top sources, top networks, source countries, most probed usernames, user
agents, recent hits.

## 6. Alerts

Alerts & AI → **Alert policies** → New policy → **Create a condition** → NRQL:

```sql
SELECT count(*) FROM Log WHERE canary = 'honeypot-canary-0001'
```

- Window: 15 minutes
- Threshold: above 20 (tune to your baseline)
- Notification: email, or a webhook if you want it in chat

That replaces a Discord ping without the chat noise. Add a second, higher
threshold (say 200 in 15 minutes) for "something is flooding us" — that is the
moment to consider the WAF challenge rule.

## 7. Cost

Free tier: 100 GB/month ingest, one full user, unlimited basic users, and ingest
stops at the cap rather than billing you. A hit is roughly 400 bytes, so the cap
is in the hundreds of millions of hits. The Log API's own limit is 300,000
requests per minute and this sends one request per hit.

Retention is short (about 8 days by default). If you want a permanent record of
scanner IPs, export query results periodically or keep a second sink.

## 8. Adding a second sink

`LOG_URL` (Discord/Slack webhook) can run alongside New Relic, but each sink
costs a subrequest: two sinks = 2, which is exactly the Pro allowance. On Free
(0 subrequests) neither sink works — read Cloudflare's own request log instead.
