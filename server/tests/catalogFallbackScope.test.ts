import { test } from "node:test";
import assert from "node:assert/strict";
import {
  runInCatalogFallbackScope,
  noteCatalogFallback,
  attachCatalogFallbacks,
} from "../src/connectionManager.js";

// The contract: when a query falls back to `master`, the warning must reach the tool RESULT —
// every tool's result, not just execute_query's. The server instructions sent to every client at
// initialize say "if a result carries catalog_fallback the connection is on master", which a
// reader correctly inverts to "no warning means the connection is fine". That inversion is only
// safe if the field genuinely rides on everything, so these tests pin the mechanism that makes it
// so: roTool runs each handler inside a collection scope and attaches whatever was collected.
//
// The concurrency test is the important one. A module-level variable would be simpler and would
// pass every other test here, then silently leak one caller's warning onto another caller's result
// on the shared HTTP transport — reporting a sick database on a node that is fine.

const content = (text: string) => ({ content: [{ type: "text" as const, text }] });

test("no fallback: the result is returned untouched", () => {
  const result = runInCatalogFallbackScope(() => attachCatalogFallbacks(content("rows")));
  assert.deepEqual(result, content("rows"));
});

test("fallback noted: the warning is prepended, the payload is preserved", () => {
  const result = runInCatalogFallbackScope(() => {
    noteCatalogFallback("region3-node1", "CONNECTED TO master, NOT AppCatalog");
    return attachCatalogFallbacks(content("rows"));
  });
  assert.equal(result.content.length, 2);
  assert.match(result.content[0].text, /CONNECTED TO master, NOT AppCatalog/);
  assert.equal(result.content[1].text, "rows", "the original payload must survive intact");
});

test("one warning per instance, even when several queries hit the same node", () => {
  const result = runInCatalogFallbackScope(() => {
    noteCatalogFallback("region3-node1", "W1");
    noteCatalogFallback("region3-node1", "W1");
    noteCatalogFallback("region3-node2", "W2");
    return attachCatalogFallbacks(content("rows"));
  });
  const banner = result.content[0].text;
  assert.equal(banner.match(/W1/g)?.length, 1, "same instance must not repeat");
  assert.match(banner, /W2/, "a second instance must still be reported (fan_out_query)");
});

test("concurrent tool calls do not leak warnings into each other", async () => {
  // Interleave deliberately: A notes, yields, B notes and finishes, then A finishes. A global
  // would hand A both warnings — and hand B one it never saw.
  const a = runInCatalogFallbackScope(async () => {
    noteCatalogFallback("region3-node1", "NODE-A-WARNING");
    await new Promise((r) => setImmediate(r));
    return attachCatalogFallbacks(content("node-a rows"));
  });
  const b = runInCatalogFallbackScope(async () => {
    noteCatalogFallback("region1-node2", "NODE-B-WARNING");
    return attachCatalogFallbacks(content("node-b rows"));
  });

  const [ra, rb] = await Promise.all([a, b]);
  assert.match(ra.content[0].text, /NODE-A-WARNING/);
  assert.doesNotMatch(ra.content[0].text, /NODE-B-WARNING/, "node B warning must not appear on node A result");
  assert.match(rb.content[0].text, /NODE-B-WARNING/);
  assert.doesNotMatch(rb.content[0].text, /NODE-A-WARNING/, "node A warning must not appear on node B result");
});

test("a scope is fresh per call: a warning does not survive into the next tool call", () => {
  runInCatalogFallbackScope(() => noteCatalogFallback("region3-node1", "STALE"));
  const next = runInCatalogFallbackScope(() => attachCatalogFallbacks(content("rows")));
  assert.deepEqual(next, content("rows"));
});

test("a non-content result is passed through unchanged", () => {
  const odd = { rows: [1, 2, 3] };
  const result = runInCatalogFallbackScope(() => {
    noteCatalogFallback("region3-node1", "W");
    return attachCatalogFallbacks(odd);
  });
  assert.deepEqual(result, odd);
});

test("noting outside a scope is a no-op rather than a crash", () => {
  assert.doesNotThrow(() => noteCatalogFallback("region3-node1", "W"));
  assert.deepEqual(attachCatalogFallbacks(content("rows")), content("rows"));
});
