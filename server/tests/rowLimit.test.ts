import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  applyRowLimit,
  capRows,
  finishQuery,
  noteRowCap,
  noteCatalogFallback,
  runInCatalogFallbackScope,
  attachCatalogFallbacks,
} from "../src/connectionManager.js";

// The contract: a result cut at the row cap must SAY it was cut. queryInstance wraps the query in
// SET ROWCOUNT and flags truncation only when MORE than maxRows rows come back, so the cap has to let
// one extra row through or the flag can never fire. It used to cap at exactly maxRows: a 2,630-row
// execute_query on a test instance returned 500 rows and no truncation note.

// What SQL Server does with the batch: SET ROWCOUNT n stops the SELECT after n rows; without it (a
// query with its own TOP (…)) everything the query produces comes back.
function serverReturns(batch: string, produced: number): number[] {
  const m = batch.match(/^SET ROWCOUNT (\d+);/m);
  const n = m ? Math.min(Number(m[1]), produced) : produced;
  return Array.from({ length: n }, (_, i) => i);
}
const roundTrip = (sql: string, produced: number, maxRows: number) =>
  capRows(serverReturns(applyRowLimit(sql, maxRows), produced), maxRows);

test("a result larger than the cap is flagged as truncated", () => {
  const r = roundTrip("SELECT o.object_id FROM sys.all_objects o", 2630, 500);
  assert.equal(r.rows.length, 500);
  assert.equal(r.truncated, true);
});

test("one row over the cap is flagged; exactly the cap, or nothing, is not", () => {
  assert.equal(roundTrip("SELECT 1", 501, 500).truncated, true);
  const exact = roundTrip("SELECT 1", 500, 500);
  assert.equal(exact.rows.length, 500);
  assert.equal(exact.truncated, false);
  assert.deepEqual(roundTrip("SELECT 1", 0, 500), { rows: [], truncated: false });
});

test("TOP without parentheses is capped and flagged; TOP (n) and an own SET ROWCOUNT are left alone", () => {
  assert.equal(roundTrip("SELECT TOP 600 name FROM sys.objects", 600, 500).truncated, true);
  assert.equal(roundTrip("SELECT TOP (600) name FROM sys.objects", 600, 500).truncated, true);
  for (const sql of ["SELECT TOP (600) name FROM sys.objects", "SET ROWCOUNT 10; SELECT name FROM sys.objects"]) {
    assert.equal(applyRowLimit(sql, 500), sql);
  }
});

test("the cap is reset after the query", () => {
  assert.equal(applyRowLimit("SELECT 1", 500), "SET ROWCOUNT 501;\nSELECT 1\nSET ROWCOUNT 0;");
});

// The flag only helps if it reaches the tool result: most handlers keep only `rows`, so queryInstance
// notes a cut into the same per-call scope that carries catalog-fallback warnings.
test("a cut noted during a tool call is prepended to its result, once per instance and cap", () => {
  const out = runInCatalogFallbackScope(() => {
    noteRowCap("region1-node2", 200);
    noteRowCap("region1-node2", 200);
    noteCatalogFallback("region1-node2", "CONNECTED TO master");
    return attachCatalogFallbacks({ content: [{ type: "text", text: "{}" }] });
  });
  assert.equal(out.content.length, 2);
  assert.equal(out.content[1].text, "{}");
  assert.equal(out.content[0].text.match(/RESULT CUT AT 200 ROWS on "region1-node2"/g)?.length, 1);
  assert.match(out.content[0].text, /CONNECTED TO master/);
});

// queryInstance itself, not just the helper: dropping its noting step must fail a test.
test("queryInstance's post-query step raises the banner for a cut, and only for a cut it is asked to", () => {
  const cut = runInCatalogFallbackScope(() => {
    assert.deepEqual(finishQuery("region3-node1", [[1, 2, 3]], 2), { rows: [1, 2], truncated: true });
    return attachCatalogFallbacks({ content: [{ type: "text", text: "{}" }] });
  });
  assert.match(cut.content[0].text, /RESULT CUT AT 2 ROWS on "region3-node1"/);
  const none = { content: [{ type: "text", text: "{}" }] };
  assert.equal(runInCatalogFallbackScope(() => { finishQuery("region3-node1", [[1, 2]], 2); return attachCatalogFallbacks(none); }), none);
  assert.equal(runInCatalogFallbackScope(() => {
    assert.equal(finishQuery("region3-node1", [[1, 2, 3]], 2, { noteTruncation: false }).truncated, true);
    return attachCatalogFallbacks(none);
  }), none);
});

// Only the first result set is returned: user SQL is told when there were more; built-in tools know their batches.
test("a user batch with several result sets says only the first is shown", () => {
  const two = runInCatalogFallbackScope(() => {
    assert.deepEqual(finishQuery("region4-node1", [[1], [2, 3]], 500, { userSql: true }).rows, [1]);
    return attachCatalogFallbacks({ content: [{ type: "text", text: "{}" }] });
  });
  assert.match(two.content[0].text, /ONLY THE FIRST OF 2 RESULT SETS on "region4-node1"/);
  const none = { content: [{ type: "text", text: "{}" }] };
  assert.equal(runInCatalogFallbackScope(() => { finishQuery("region4-node1", [[1], [2]], 500); return attachCatalogFallbacks(none); }), none);
});

test("a batch with no result set returns no rows instead of crashing", () => {
  assert.deepEqual(finishQuery("test-node1", [], 500), { rows: [], truncated: false });
  assert.deepEqual(finishQuery("test-node1", undefined, 500), { rows: [], truncated: false });
});

// A `TOP (` in a comment or string used to switch the cap off for the whole batch (measured: a query with
// the literal 'top (literal)' returned all 2,630 rows), and user SQL never needs the exemption at all.
test("only a real TOP (…) exempts a built-in batch, and user SQL is always capped", () => {
  for (const sql of ["SELECT name FROM sys.objects -- top (", "SELECT name FROM sys.objects WHERE name <> 'top (x)'",
                     "/* TOP (1) */ SELECT name FROM sys.objects"]) {
    assert.notEqual(applyRowLimit(sql, 500), sql, `exempted by noise: ${sql}`);
  }
  assert.equal(applyRowLimit("SELECT TOP (5) name FROM sys.objects", 500), "SELECT TOP (5) name FROM sys.objects");
  // An apostrophe in a comment must not hide the batch's real TOP (…) from the exemption (shared stripNoise):
  // the old stripNoise opened a string at it and ran to the next quote, swallowing the TOP.
  const commented = "-- don't touch\nSELECT TOP (5) name FROM sys.objects WHERE name <> 'x'";
  assert.equal(applyRowLimit(commented, 500), commented);
  for (const sql of ["SELECT TOP (600) name FROM sys.objects", "SELECT name FROM sys.objects WHERE 1 = (SELECT TOP (1) 1)"]) {
    assert.equal(applyRowLimit(sql, 500, { userSql: true }), `SET ROWCOUNT 501;\n${sql}\nSET ROWCOUNT 0;`);
  }
});

test("a cut noted outside a tool call is dropped, not leaked into the next one", () => {
  noteRowCap("region1-node2", 200);
  const r = { content: [{ type: "text", text: "x" }] };
  assert.equal(runInCatalogFallbackScope(() => attachCatalogFallbacks(r)), r);
});

// SET ROWCOUNT caps EVERY statement in the batch, not just the final SELECT, so a batch that fills a
// temp table or variable first must carry its own TOP (…) to stay unwrapped. get_index_usage_stats and
// get_columnstore_health did not: each database's INSERT kept an arbitrary capped subset of its rows.
// Scope: only the template literal passed straight to queryInstance is read. SQL built in a variable
// (get_hiq's sqlText) or interpolated from a constant (${DUMP_DIR_DECLARE}) is not; neither hides one today.
test("no capped tool batch has an intermediate INSERT, UPDATE, DELETE, SELECT … INTO or variable assignment", () => {
  const offenders: string[] = [];
  for (const file of ["../src/tools.ts", "../src/dbatools.ts"]) {
    const src = readFileSync(new URL(file, import.meta.url), "utf8");
    for (const m of src.matchAll(/queryInstance\(\s*[\w.]+\s*,\s*`/g)) {
      const start = m.index! + m[0].length;
      let i = start, depth = 0;
      while (i < src.length) {
        if (src[i] === "\\") { i += 2; continue; }
        if (src[i] === "$" && src[i + 1] === "{") depth++;
        else if (src[i] === "}" && depth) depth--;
        else if (src[i] === "`" && !depth) break;
        i++;
      }
      const batch = src.slice(start, i).replace(/--[^\n]*/g, "");
      if (applyRowLimit(batch, 200) === batch) continue; // exempt: carries its own TOP (…) or SET ROWCOUNT
      if (/\bINSERT\s+(INTO\s+)?[#@\w[]/i.test(batch) || /\bSELECT\b[^;]*?\bINTO\s+#/is.test(batch) ||
          /\bSELECT\s+@\w+\s*=/i.test(batch) || /\bUPDATE\s+[#@\w[]/i.test(batch) ||
          /\bDELETE\s+(FROM\s+)?[#@\w[]/i.test(batch)) {
        offenders.push(`${file}:${src.slice(0, m.index).split("\n").length}`);
      }
    }
  }
  assert.deepEqual(offenders, []);
});
