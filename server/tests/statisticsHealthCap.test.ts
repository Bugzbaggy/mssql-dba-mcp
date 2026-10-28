import { test } from "node:test";
import assert from "node:assert/strict";
import { selectStatsObjects } from "../src/tools.ts";

// get_statistics_health (dbatools path, DBATOOLS_FIRST=1): Get-DbaDbccStatistic issues one
// DBCC SHOW_STATISTICS round trip per statistics object with no cap of its own — an
// uncapped N+1 that can hit thousands of round trips on a database with many indexed
// tables. selectStatsObjects is the truncation decision that bounds it via max_objects,
// split out so it's testable without a live SQL Server / dbatools worker.
test("selectStatsObjects returns everything untruncated when under the cap", () => {
  const { selected, truncated } = selectStatsObjects(["dbo.A", "dbo.B", "dbo.C"], 10);
  assert.deepEqual(selected, ["dbo.A", "dbo.B", "dbo.C"]);
  assert.equal(truncated, false);
});

test("selectStatsObjects caps at max_objects and reports truncated when there are more candidates", () => {
  const names = Array.from({ length: 500 }, (_, i) => `dbo.Table${String(i).padStart(4, "0")}`);
  const { selected, truncated } = selectStatsObjects(names, 50);
  assert.equal(selected.length, 50);
  assert.equal(truncated, true);
  assert.deepEqual(selected, names.slice(0, 50));
});

test("selectStatsObjects is not truncated exactly AT the cap (boundary)", () => {
  const names = Array.from({ length: 50 }, (_, i) => `dbo.Table${i}`);
  const { selected, truncated } = selectStatsObjects(names, 50);
  assert.equal(selected.length, 50);
  assert.equal(truncated, false);
});
