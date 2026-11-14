// Behaviour tests for snippet/honeypot.js.
//
// The snippet is a Cloudflare Snippets module: `export default { fetch }`.
// There is no build step, so these tests load the real file, optionally rewrite
// a CONFIG value, and exercise it with mocked requests and a mocked fetch.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const SOURCE = readFileSync(new URL("../snippet/honeypot.js", import.meta.url), "utf8");
const DIR = mkdtempSync(join(tmpdir(), "honeypot-"));
let seq = 0;

const VALUE = String.raw`(?:"(?:[^"\\]|\\.)*"|true|false|\[[^\]]*\])`;

async function load(overrides = {}) {
  let code = SOURCE;
  for (const [key, value] of Object.entries(overrides)) {
    const re = new RegExp(`(\\b${key}:\\s*)${VALUE}`);
    assert.ok(re.test(code), `CONFIG.${key} not found in the snippet`);
    code = code.replace(re, `$1${JSON.stringify(value)}`);
  }
  const file = join(DIR, `snippet-${seq++}.mjs`);
  writeFileSync(file, code);
  const mod = await import(pathToFileURL(file).href);
  return mod.default;
}

// Mock the global fetch the snippet uses for its two jobs: forwarding to the
// origin, and posting to a log sink.
function mockFetch({ sinkFails = false } = {}) {
  const calls = { origin: 0, sinks: [] };

  globalThis.fetch = async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);

    if (url.includes("newrelic") || url.includes("discord") || url.includes("webhook")) {
      if (sinkFails) throw new Error("sink is down");
      calls.sinks.push({ url, body: init && init.body });
      return new Response("{}", { status: 202 });
    }

    calls.origin++;
    return new Response('{"real":true}', {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  return calls;
}

const HOST = "https://forum.example.com";
const SCANNER = { "user-agent": "curl/8.4.0", accept: "application/json" };
const req = (path, headers = SCANNER, init = {}) =>
  new Request(HOST + path, { headers, ...init });

test("scanner gets a fabricated profile, origin untouched", async () => {
  const calls = mockFetch();
  const snippet = await load();
  const res = await snippet.fetch(req("/u/queensarahz.json"));

  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /application\/json/);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.ok(res.headers.get("x-honeypot"), "canary header missing");

  const body = await res.json();
  assert.equal(body.user.username, "queensarahz");
  assert.ok(body.user._hp, "canary field missing");
  assert.ok(body.user.id > 0);
  assert.match(body.user.avatar_template, /^\/user_avatar\//);
  assert.equal(calls.origin, 0, "origin must not be contacted for a probe");
});

test("the same username always yields the same profile", async () => {
  mockFetch();
  const snippet = await load();
  const a = await (await snippet.fetch(req("/u/teemo.json"))).json();
  const b = await (await snippet.fetch(req("/u/teemo.json"))).json();
  assert.equal(a.user.id, b.user.id);
  assert.equal(a.user.created_at, b.user.created_at);
});

test("real visitors are passed through", async () => {
  const cases = {
    "session cookie": { cookie: "_forum_session=abc123", accept: "application/json" },
    "session token": { cookie: "_t=xyz", accept: "application/json" },
    "same-site referer": { referer: HOST + "/u/teemo", accept: "application/json" },
    "browser navigation": { accept: "text/html,application/xhtml+xml" },
    "discourse api client": { "api-key": "abc", "api-username": "system" },
  };

  for (const [name, headers] of Object.entries(cases)) {
    const calls = mockFetch();
    const snippet = await load();
    const res = await snippet.fetch(req("/u/teemo.json", headers));
    assert.equal(res.status, 200, name);
    assert.equal(calls.origin, 1, `${name} should reach the origin`);
    assert.equal(calls.sinks.length, 0, `${name} should not be logged`);
  }
});

test("unrelated paths are never trapped", async () => {
  const paths = ["/latest.json", "/u/teemo/summary.json", "/u/teemo", "/srv/pv", "/"];

  for (const path of paths) {
    const calls = mockFetch();
    const snippet = await load();
    const res = await snippet.fetch(req(path));
    assert.equal(res.status, 200, path);
    assert.equal(calls.origin, 1, `${path} should reach the origin`);
  }
});

test("avatar probes get a real PNG", async () => {
  const calls = mockFetch();
  const snippet = await load();

  for (const path of [
    "/user_avatar/forum.example.com/",
    "/user_avatar/forum.example.com/teemo/96/1234_2.png",
  ]) {
    const res = await snippet.fetch(req(path, { "user-agent": "curl/8.4.0", accept: "*/*" }));
    assert.equal(res.status, 200, path);
    assert.equal(res.headers.get("content-type"), "image/png", path);

    const bytes = new Uint8Array(await res.arrayBuffer());
    assert.equal(bytes.length, 226, "unexpected PNG size");
    assert.deepEqual(
      [...bytes.slice(0, 8)],
      [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
      "bad PNG signature"
    );
    // PNG ends with the IEND chunk followed by its CRC.
    assert.deepEqual([...bytes.slice(-8, -4)], [0x49, 0x45, 0x4e, 0x44], "missing IEND chunk");
  }

  assert.equal(calls.origin, 0);
});

test("avatar requests from real visitors are passed through", async () => {
  const calls = mockFetch();
  const snippet = await load();
  await snippet.fetch(
    req("/user_avatar/forum.example.com/teemo/96/1234_2.png", {
      cookie: "_forum_session=abc",
      accept: "image/avif,image/webp,*/*",
    })
  );
  assert.equal(calls.origin, 1);
});

test("logging is off when no sink is configured", async () => {
  const calls = mockFetch();
  const snippet = await load();
  await snippet.fetch(req("/u/teemo.json"));
  assert.equal(calls.sinks.length, 0, "no sink configured means no subrequest");
});

test("a New Relic sink receives one log entry per hit", async () => {
  const calls = mockFetch();
  const snippet = await load({ NEW_RELIC_LICENSE_KEY: "test-key" });

  await snippet.fetch(req("/u/teemo.json"));
  await snippet.fetch(req("/user_avatar/forum.example.com/", { accept: "*/*" }));

  assert.equal(calls.sinks.length, 2);
  const entries = calls.sinks.map((c) => JSON.parse(c.body)[0]);
  assert.deepEqual(
    entries.map((e) => e.attributes.trap).sort(),
    ["avatar", "profile"]
  );

  const profile = entries.find((e) => e.attributes.trap === "profile");
  assert.equal(profile.attributes.username, "teemo");
  assert.equal(profile.attributes.event, "honeypot_hit");
  assert.ok(profile.attributes.canary);
  assert.ok(profile.attributes.ip !== undefined);
  assert.match(profile.message, /honeypot hit \[profile\]/);
});

test("a failing sink never breaks the trap", async () => {
  mockFetch({ sinkFails: true });
  const snippet = await load({ NEW_RELIC_LICENSE_KEY: "test-key" });
  const res = await snippet.fetch(req("/u/teemo.json"));
  assert.equal(res.status, 200);
  assert.ok((await res.json()).user._hp);
});

test("traps can be switched off individually", async () => {
  let calls = mockFetch();
  let snippet = await load({ AVATAR_TRAP: false });
  await snippet.fetch(req("/user_avatar/forum.example.com/", { accept: "*/*" }));
  assert.equal(calls.origin, 1, "avatar trap disabled should pass through");

  calls = mockFetch();
  snippet = await load({ PROFILE_TRAP: false });
  await snippet.fetch(req("/u/teemo.json"));
  assert.equal(calls.origin, 1, "profile trap disabled should pass through");
});

test("PROBE_ORIGIN stays off: probes cost the origin nothing", async () => {
  const calls = mockFetch();
  const snippet = await load({ PROBE_ORIGIN: false });
  await snippet.fetch(req("/u/teemo.json"));
  await snippet.fetch(req("/u/ghost.json"));
  assert.equal(calls.origin, 0);
});
