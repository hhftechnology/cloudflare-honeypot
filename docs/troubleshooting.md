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

## The dashboard is empty

- Set the time range to 7 days. The default 30 minutes is usually empty.
- `accountId` in the imported JSON must be your account id, not `0`.
- The canary in the dashboard queries must match `CONFIG.CANARY` exactly.

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
