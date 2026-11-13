# Troubleshooting

## The trap does not fire

Test like a scanner — no cookie, no referer, `Accept: */*`:

```bash
curl -s -H 'Accept: */*' https://forum.example.com/u/nosuchuser999.json -D - -o /dev/null | grep -i x-honeypot
```

No `x-honeypot` header means the snippet never ran. Check, in order:

1. **Is the snippet rule attached?** A snippet with no rule is inert. Rules →
   Snippets → the rule must exist and be enabled.
2. **Does the expression match?** `http.request.uri.path wildcard "/u/*.json"`.
   URI **Full** includes the query string and will not match `/u/x.json?a=1`.
3. **Is the hostname proxied?** Snippets do not run on DNS-only records.
4. **Did a WAF rule fire first?** A `block` or challenge on the same path ends
   the request before the snippet phase.
5. **Snippet slots.** If the zone is at its limit the deploy silently leaves the
   snippet unused — check for an "Unused Snippets" tab.

## The trap fires for real users

Symptom: a real person sees fake JSON, or a member's profile page fails to load.

- Check the filters: a client with `_forum_session` or a same-host `Referer`
  must pass through. If you narrowed `SESSION_COOKIES`, you may have removed the
  one your platform sets for anonymous visitors.
- Discourse sets `_forum_session` for anonymous visitors too. XenForo sets
  `xf_session`. Confirm in your browser's dev tools.
- Add `Accept: text/html` to the pass-through list if you removed it — that is
  what protects people pasting the URL into the address bar.

## Nothing reaches New Relic

1. **Wrong key type.** It must be an *Ingest – license* key, not `NRAK-…` and not
   a browser key. A 403 from the Log API is silent from the snippet's side.
2. **Wrong region.** US `log-api.newrelic.com`, EU `log-api.eu.newrelic.com`,
   Japan `log-api.jp.nr-data.net`.
3. **No subrequests on your plan.** Free allowance is 0, so the `fetch` is
   blocked. Use Cloudflare's own request log, or move to a plan with subrequests.
4. **Subrequest budget exhausted.** Two sinks = 2 subrequests = the Pro limit.
5. **Looking in the wrong place.** Use **Query your data**, not the Logs search
   box, and give it a minute. Logs UI defaults to a 30-minute window.

```sql
SELECT count(*) FROM Log WHERE canary = 'honeypot-canary-0001' SINCE 1 day ago
```

## Discord shows the message, New Relic does not (or vice versa)

Each sink is independent. Both are attempted and either can fail without
affecting the other or the fake response — verified by forcing a network
failure. Compare the two config keys: `LOG_URL` and `NEW_RELIC_LICENSE_KEY`.

## Dashboard import fails: `Failed to create dashboard` / Schema

The importer validates the JSON before it creates anything, so this is a schema
problem, not a data problem. In order of likelihood:

1. **`accountId: 0` still in the file.** The dashboard ships with zeros as a
   placeholder. Zero is not an account and validation rejects it. There are
   eleven occurrences — replace them all with your own account id (account
   switcher bottom-left, or `one.newrelic.com/accounts/<id>/…`).

   ```bash
   sed -i 's/"accountId": 0/"accountId": 1234567/g' dashboards/newrelic-honeypot.json
   ```

2. **Layout outside the grid.** New Relic uses a 12-column grid: `column` and
   `width` are 1–12 and `column + width - 1` may not exceed 12. If you edited
   the layout by hand, this is what broke.

3. **Not a dashboard export.** The top level must be
   `{name, permissions, pages:[{name, widgets:[…]}]}`. A single widget, or a
   NerdGraph mutation payload, will not import.

**Bisect it:** import a one-widget dashboard containing only a `viz.markdown`
widget and no queries at all. If that imports, the wrapper is fine and the
problem is in the query objects (i.e. `accountId`). If it fails, the wrapper is
wrong — compare it against `Download dashboard` → JSON from any existing
dashboard in your account.

**Fallback that cannot fail:** Query your data → run the NRQL → **Add to
dashboard**. It builds against the live schema instead of a pasted file.

## The dashboard imported but shows zeros

The widgets filter on the canary. If you changed `CANARY` in the snippet (you
should) and left `honeypot-canary-0001` in the dashboard, every query matches
nothing. Replace all eleven occurrences of the canary string.

Also check the time range — the default is often 30 minutes. Set it to 7 days.

## `matches` is rejected by the dashboard

```
not entitled: the use of operator Matches is not allowed
```

Regex needs Business or WAF Advanced. Use `wildcard`; the snippet re-checks the
path itself.

## Origin load did not go down

Check `PROBE_ORIGIN`. If it is `true`, every probe costs one origin request. Set
it to `false` — the header filters are what protect real visitors, not an origin
round trip.

## Logs disappeared after a week

Free-tier retention is short (about 8 days by default). Export the queries you
care about, or add a second sink that keeps data longer.
