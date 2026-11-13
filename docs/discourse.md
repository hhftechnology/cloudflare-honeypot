# Discourse specifics

## `/u/<username>.json` is a real endpoint

Discourse serves a member's profile JSON at `GET /u/<username>.json` — its own
test suite asserts it. So the trap must never answer for a real visitor, or you
break profile pages for logged-out users.

The snippet therefore decides from the request's own headers, with no origin
round trip:

| Real Discourse client sends | Result |
| --- | --- |
| `_forum_session` cookie — Discourse sets this for **anonymous** visitors too | pass through |
| `_t` cookie (session token) | pass through |
| `Referer` from your host | pass through |
| `Api-Key` / `Api-Username` (API clients, mobile apps) | pass through |
| `Accept: text/html` (URL pasted in a browser) | pass through |
| none of the above | fake profile |

That is why `PROBE_ORIGIN` is unnecessary on Discourse and should stay `false`:
the filters are sufficient, and an origin check would put a request back on your
server for every probe — the opposite of the point.

## What the scanners are actually doing

A wordlist walk against random names:

```
/u/kortney_renee.json        404
/u/dry_efficiency889.json    404
/u/10793348878852646808.json 404
/u/Barry.The.Locksmith.json  404
```

Random casing, underscores, dots, and occasional numeric IDs. None of these
exist, and Discourse answers 404 for each — cheap for them, a wasted worker for
you. The trap turns each one into a logged, useless 200.

## Sub-routes are untouched

The snippet only matches `/u/<one segment>.json`. These are unaffected:

- `/u/<name>/summary.json`
- `/u/<name>/card.json`
- `/u/<name>/activity.json`
- `/u/<name>` (the HTML profile page)

A broad `wildcard` rule will match some of these at the rule level; the snippet's
own path check rejects them and forwards to the origin.

## The cheaper lever

Discourse has a site setting **`hide user profiles from public`**
(Admin → Settings → Users). With it on, `/u/<username>.json` returns **403** to
anyone logged out, so anonymous enumeration dies at the source.

- Cost: logged-out visitors and crawlers lose profile pages. `/u` routes are
  already `noindex`, so search impact is small.
- If public profiles do not matter to you, turn it on and skip this repo.
- If they do, keep the trap — and consider both.

## Other forums

| Platform | Endpoint shape | Session cookie |
| --- | --- | --- |
| Discourse | `/u/<name>.json` | `_forum_session`, `_t` |
| XenForo | `/members/<name>.<id>/` | `xf_session`, `xf_user` |
| Flarum | `/u/<name>` | `flarum_session` |
| WordPress | `/author/<name>/` | `wordpress_logged_in_*` |

Change the path regex in the snippet and `SESSION_COOKIES` to match. The profile
shape returned by `fakeProfile()` is Discourse-flavoured; adjust the fields if
your platform's scanners expect something else.
