// Schema tests for dashboards/newrelic-honeypot.json.
//
// These mirror the rules New Relic enforces on import, so a broken dashboard is
// caught in CI instead of in the import dialog:
//   - 12-column grid, column + width - 1 <= 12
//   - no overlapping widgets
//   - every widget has a layout, a viz.* visualisation and NRQL queries
//   - every query carries an integer accountId and a Log query filtered on canary

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const raw = readFileSync(
  new URL("../dashboards/newrelic-honeypot.json", import.meta.url),
  "utf8"
);
const dashboard = JSON.parse(raw);

const ALLOWED_PERMISSIONS = ["PUBLIC_READ_WRITE", "PUBLIC_READ_ONLY", "PRIVATE"];
const GRID_COLUMNS = 12;

const widgets = dashboard.pages.flatMap((page) => page.widgets);
const queries = widgets.flatMap((w) => (w.rawConfiguration?.nrqlQueries ?? []));

test("top level matches the dashboard import shape", () => {
  assert.equal(typeof dashboard.name, "string");
  assert.ok(dashboard.name.length > 0);
  assert.ok(ALLOWED_PERMISSIONS.includes(dashboard.permissions), "bad permissions value");
  assert.ok(Array.isArray(dashboard.pages) && dashboard.pages.length > 0, "no pages");
  for (const page of dashboard.pages) {
    assert.ok(Array.isArray(page.widgets) && page.widgets.length > 0, "page without widgets");
  }
});

test("every widget is complete", () => {
  for (const widget of widgets) {
    assert.equal(typeof widget.title, "string", "widget title missing");

    const { layout, visualization, rawConfiguration } = widget;
    assert.ok(layout, `${widget.title}: no layout`);
    assert.ok(visualization && typeof visualization.id === "string", `${widget.title}: no visualisation`);
    assert.match(visualization.id, /^viz\./, `${widget.title}: bad visualisation id`);
    assert.ok(rawConfiguration, `${widget.title}: no rawConfiguration`);

    if (visualization.id !== "viz.markdown") {
      assert.ok(
        Array.isArray(rawConfiguration.nrqlQueries) && rawConfiguration.nrqlQueries.length > 0,
        `${widget.title}: no NRQL queries`
      );
    }
  }
});

test("titles are unique", () => {
  const seen = new Set();
  for (const widget of widgets) {
    assert.ok(!seen.has(widget.title), `duplicate widget title: ${widget.title}`);
    seen.add(widget.title);
  }
});

test("layout stays inside New Relic's 12-column grid", () => {
  for (const widget of widgets) {
    const { column, row, width, height } = widget.layout;
    for (const [key, value] of Object.entries({ column, row, width, height })) {
      assert.equal(typeof value, "number", `${widget.title}: ${key} is not a number`);
      assert.ok(Number.isInteger(value), `${widget.title}: ${key} is not an integer`);
    }
    assert.ok(column >= 1 && column <= GRID_COLUMNS, `${widget.title}: column ${column} out of range`);
    assert.ok(width >= 1 && width <= GRID_COLUMNS, `${widget.title}: width ${width} out of range`);
    assert.ok(row >= 1, `${widget.title}: row ${row} out of range`);
    assert.ok(height >= 1, `${widget.title}: height ${height} out of range`);
    assert.ok(
      column + width - 1 <= GRID_COLUMNS,
      `${widget.title}: column ${column} + width ${width} overflows the grid`
    );
  }
});

test("widgets do not overlap", () => {
  const taken = new Map();
  for (const widget of widgets) {
    const { column, row, width, height } = widget.layout;
    for (let r = row; r < row + height; r++) {
      for (let c = column; c < column + width; c++) {
        const key = `${r}:${c}`;
        assert.ok(!taken.has(key), `${widget.title} overlaps ${taken.get(key)} at ${key}`);
        taken.set(key, widget.title);
      }
    }
  }
});

test("every query targets the Log event type and filters on a canary", () => {
  assert.ok(queries.length > 0, "no queries found");

  for (const q of queries) {
    assert.equal(typeof q.query, "string");
    assert.match(q.query, /\bFROM\s+Log\b/i, `query does not read from Log: ${q.query}`);
    assert.match(q.query, /canary\s*=\s*'[^']+'/i, `query is not canary-filtered: ${q.query}`);
  }
});

test("the canary is consistent across every query", () => {
  const canaries = new Set(
    queries
      .map((q) => q.query.match(/canary\s*=\s*'([^']+)'/i))
      .filter(Boolean)
      .map((m) => m[1])
  );
  assert.equal(canaries.size, 1, `mixed canary values: ${[...canaries].join(", ")}`);
});

test("accountId is an integer and identical everywhere", () => {
  const ids = new Set(queries.map((q) => q.accountId));
  for (const id of ids) {
    assert.equal(typeof id, "number", "accountId must be a number");
    assert.ok(Number.isInteger(id) && id >= 0, "accountId must be a non-negative integer");
  }
  assert.equal(ids.size, 1, `mixed accountId values: ${[...ids].join(", ")}`);
});

test("the shipped file still uses the documented placeholders", () => {
  // The public repo must never carry a real account id or canary.
  assert.ok(
    queries.every((q) => q.accountId === 0),
    "dashboards/newrelic-honeypot.json must ship with accountId 0 as a placeholder"
  );
  assert.ok(
    queries.some((q) => q.query.includes("honeypot-canary-0001")),
    "the placeholder canary should be honeypot-canary-0001"
  );
});
