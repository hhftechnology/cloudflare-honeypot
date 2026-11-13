/**
 * cloudflare-honeypot - fake-profile trap for user enumeration scans
 * Cloudflare Snippet (Rules -> Snippets). One snippet slot.
 *
 * Any request to /u/<name>.json that no real client would make gets a 200 with
 * a believable but entirely fake profile. Real visitors are passed through to
 * the origin untouched, and the origin never sees a probe.
 *
 * LIMITS THIS RESPECTS
 *   5 ms CPU, 2 MB memory, 32 KB package, no KV, no bindings, no environment
 *   variables - every setting lives inline in CONFIG below.
 */

const CONFIG = {
  // Marker stamped into every fake response and into the fake email address.
  // Change it to something unique to you, then grep your logs (or the web) for
  // it to see where the poisoned data ended up.
  CANARY: "honeypot-canary-0001",

  // ---- Where hits go. Both sinks are optional and independent. ----
  // Each one costs a subrequest: Pro allows 2, Business 3, Free 0.

  // New Relic Log API. Use a LICENSE key (Ingest - license), not a user key.
  //   US     https://log-api.newrelic.com/log/v1
  //   EU     https://log-api.eu.newrelic.com/log/v1
  //   Japan  https://log-api.jp.nr-data.net/log/v1
  NEW_RELIC_LICENSE_KEY: "",
  NEW_RELIC_ENDPOINT: "https://log-api.newrelic.com/log/v1",

  // Optional second sink: a Discord/Slack webhook. "" disables it.
  LOG_URL: "",

  // LEAVE THIS OFF. Turning it on sends one request to your origin for every
  // probe - exactly the load this trap exists to remove. With it off, matched
  // traffic is answered at Cloudflare's edge and your server never sees it.
  //
  // If you do enable it: it needs snippet subrequests (Pro+), and the snippet
  // rule expression must exclude the probe marker or the subrequest will loop.
  PROBE_ORIGIN: false,

  // Cookies that mean "this is a real visitor, leave them alone".
  // Discourse sets _forum_session for anonymous visitors too, so this alone
  // excludes every real browser. XenForo: xf_session, xf_user.
  // WordPress: wordpress_logged_in_*, woocommerce_items_in_cart.
  SESSION_COOKIES: ["_forum_session", "_t"],

  // Response headers for the fake profile.
  CONTENT_TYPE: "application/json; charset=utf-8",
};

/* ---------- helpers ---------- */

function hash32(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function prettyName(username) {
  return username
    .replace(/[._-]+/g, " ")
    .replace(/\b[a-z]/g, (c) => c.toUpperCase());
}

// Deterministic per username, so a bot that comes back for the same name sees a
// stable profile and cannot tell it is being fed garbage.
function fakeProfile(username, host) {
  const h = hash32(username.toLowerCase());
  const id = 1000 + (h % 90000);
  const level = 1 + (h % 3);
  const year = 2015 + (h % 9);
  const month = 1 + (h % 12);
  const day = 1 + (h % 27);
  const pad = (n) => String(n).padStart(2, "0");

  return {
    user: {
      id: id,
      username: username,
      name: prettyName(username),
      avatar_template: `/user_avatar/${host}/${username}/{size}/${id}_2.png`,
      created_at: `${year}-${pad(month)}-${pad(day)}T09:14:22.000Z`,
      last_seen_at: "2026-11-12T18:41:07.000Z",
      last_posted_at: "2026-11-11T07:02:55.000Z",
      trust_level: level,
      admin: false,
      moderator: false,
      staff: false,
      post_count: h % 400,
      time_read: h % 90000,
      days_visited: h % 900,
      // Deliberate bait: any harvested address traces back to this trap.
      email: `${CONFIG.CANARY}.${id}@${host}`,
      groups: [{ id: 10 + level, name: `trust_level_${level}` }],
      _hp: CONFIG.CANARY,
    },
  };
}

function looksLikeRealVisitor(request, host) {
  const h = request.headers;

  const cookie = h.get("Cookie") || "";
  if (CONFIG.SESSION_COOKIES.some((c) => cookie.includes(c + "="))) return true;

  const referer = h.get("Referer") || "";
  if (referer.includes("//" + host + "/") || referer.includes("//" + host + "?")) return true;

  // Discourse API clients (apps, integrations, admin scripts).
  if (h.get("Api-Key") || h.get("Api-Username")) return true;

  // A person pasting the URL into the address bar wants the HTML page.
  const accept = h.get("Accept") || "";
  if (accept.includes("text/html")) return true;

  return false;
}

// One log entry per hit, shaped for the New Relic Log API: an array of log
// objects, each with message / timestamp / attributes. Attribute names become
// queryable NRQL fields.
async function logHit(request, url, username) {
  const h = request.headers;
  const cf = request.cf || {};
  const hit = {
    event: "honeypot_hit",
    host: url.hostname,
    path: url.pathname,
    username: username,
    query: url.search ? url.search.slice(0, 200) : "",
    ip: h.get("cf-connecting-ip") || "",
    asn: cf.asn || 0,
    as_org: cf.asOrganization || "",
    country: cf.country || "",
    region: cf.region || "",
    city: cf.city || "",
    colo: cf.colo || "",
    http_protocol: cf.httpProtocol || "",
    tls_version: cf.tlsVersion || "",
    method: request.method,
    ua: (h.get("User-Agent") || "").slice(0, 300),
    accept: (h.get("Accept") || "").slice(0, 120),
    accept_language: (h.get("Accept-Language") || "").slice(0, 80),
    referer: (h.get("Referer") || "").slice(0, 300),
    canary: CONFIG.CANARY,
  };

  // One readable line, so a plain log table is useful without opening the
  // attributes panel.
  const line =
    `honeypot hit ${hit.host}${hit.path} | ip ${hit.ip} | ` +
    `asn ${hit.asn} ${hit.as_org} | ${hit.country}${hit.city ? " / " + hit.city : ""} | ` +
    `${hit.ua || "no user-agent"}`;

  const jobs = [];

  if (CONFIG.NEW_RELIC_LICENSE_KEY) {
    jobs.push(
      fetch(CONFIG.NEW_RELIC_ENDPOINT, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "api-key": CONFIG.NEW_RELIC_LICENSE_KEY,
        },
        body: JSON.stringify([
          { message: line, timestamp: Date.now(), attributes: hit },
        ]),
      })
    );
  }

  if (CONFIG.LOG_URL) {
    jobs.push(
      fetch(CONFIG.LOG_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ content: line }),
      })
    );
  }

  // Never let logging break the trap.
  await Promise.allSettled(jobs);
}

/* ---------- the snippet ---------- */

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const host = url.hostname;

    const match = url.pathname.match(/^\/u\/([^\/]+)\.json$/i);
    if (!match) return fetch(request);

    let username = match[1];
    try {
      username = decodeURIComponent(username);
    } catch (e) {
      /* keep the raw form */
    }

    // Never touch a real visitor's session.
    if (looksLikeRealVisitor(request, host)) return fetch(request);

    // Optional origin check: only poison paths the origin does not have.
    if (CONFIG.PROBE_ORIGIN) {
      const probe = new URL(request.url);
      probe.searchParams.set("hp_probe", "1");
      const real = await fetch(probe.toString(), {
        method: "GET",
        headers: { "x-honeypot-probe": "1" },
      });
      if (real.status !== 404) return real;
    }

    // Log the hit. A failed sink must never stop the fake response.
    if (CONFIG.NEW_RELIC_LICENSE_KEY || CONFIG.LOG_URL) {
      await logHit(request, url, username);
    }

    return new Response(JSON.stringify(fakeProfile(username, host)), {
      status: 200,
      headers: {
        "content-type": CONFIG.CONTENT_TYPE,
        "cache-control": "no-store",
        "x-honeypot": CONFIG.CANARY,
      },
    });
  },
};
