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

Either import `dashboards/newrelic-honeypot.json` (Dashboards → Import, after
replacing `accountId` and the canary string), or create it from the script:

```bash
export NEW_RELIC_ACCOUNT_ID=1234567
export NEW_RELIC_USER_KEY=NRAK-...
export HONEYPOT_CANARY=honeypot-canary-0001   # optional
bash scripts/create-dashboard.sh
```

The script uses NerdGraph (`dashboardCreate`) and needs a **user** key, not a
license key. EU accounts: also export
`NERDGRAPH_ENDPOINT=https://api.eu.newrelic.com/graphql`.

Eleven widgets: total hits, unique IPs, usernames probed, countries, hits over
time, top sources, top networks, source countries, most probed usernames, user
agents, recent hits. Set the dashboard time range to 7 days — the default 30
minutes will usually be empty.

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
