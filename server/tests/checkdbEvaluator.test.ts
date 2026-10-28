/**
 * "Last good CHECKDB" evaluator guards.
 *
 * This is the anchor of the Recoverability score and it used to have a hole: it filtered
 * out every row with no LastGoodCheckDb BEFORE taking the maximum age — i.e. it dropped
 * exactly the databases that have never been checked, which is the population the check
 * exists to find. With nothing scored, $mx was $null, and `$null -ge 30` is False in
 * PowerShell, so an instance where NOTHING had ever been CHECKDB'd graded 'pass'.
 *
 * The evaluator is PowerShell, so the behaviour was verified by running it in pwsh over
 * Get-DbaLastGoodCheckDb rows shaped like a real node's (most databases never checked, a few
 * dated-stale). Results, old -> new:
 *
 *   never-checked DBs plus one checked thousands of days ago      fail      -> fail
 *   after CHECKDB on the dated-stale DBs (the rest unchecked)      pass      -> FAIL
 *   nothing has EVER been CHECKDB-ed                               pass      -> FAIL
 *   every database checked today                                   pass      -> pass
 *   healthy + a 3-day-old DB pending its first run                 pass      -> pass
 *   all checked 20 days ago                                        attention -> attention
 *   tempdb alone (never persists a last-known-good)                pass      -> pass
 *
 * Two real improvements, no regressions, no false positives. This test pins the structural
 * guards that produce that behaviour so they cannot be dropped in a later edit.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG } from "../src/dbatools.js";

const entry = CATALOG.find((c) => c[1] === "Last good CHECKDB");
const evaluator = String(entry?.[6] ?? "");

test("the evaluator counts databases that have never been checked", () => {
  assert.ok(entry, "the Last good CHECKDB entry must exist");
  assert.match(evaluator, /\$null -eq \$_\.LastGoodCheckDb/,
    "never-checked rows (LastGoodCheckDb $null) must be counted, not filtered away");
  assert.match(evaluator, /LastGoodCheckDb\.Year -le 2000/,
    "a 1900 boot-page date is also 'never checked' and must be counted");
});

test("an instance where nothing was ever checked cannot grade pass", () => {
  // The bug was structural: with no row scored, $mx is $null and `$null -ge 30` is False,
  // so every branch fell through to 'pass'. The fix must gate on the never-checked COUNT
  // as well, and must null-guard $mx rather than relying on comparison against $null.
  assert.match(evaluator, /\$n\.Count/,
    "the fail branch must fire on the never-checked count, not only on the max age");
  assert.match(evaluator, /\$null -ne \$mx/,
    "$mx must be null-guarded - `$null -ge 30` is False and silently means 'pass'");
});

test("tempdb and brand-new databases are exempt, so the check cannot fail forever", () => {
  assert.match(evaluator, /tempdb/,
    "tempdb never persists a last-known-good and would otherwise fail permanently");
  assert.match(evaluator, /DaysSinceDbCreated -ge 30/,
    "a database younger than the fail threshold has not yet missed a scheduled run");
  // `$null -lt 30` is True in PowerShell, so a row missing the property would be dropped
  // instead of flagged without this guard.
  assert.match(evaluator, /\$null -eq \$_\.DaysSinceDbCreated -or/,
    "the DaysSinceDbCreated guard must be null-safe or it silently drops rows");
});

test("the attention band is still reachable", () => {
  assert.match(evaluator, /-ge 14/, "14-30 days must still grade attention, not jump to fail");
  assert.match(evaluator, /'attention'/);
  assert.match(evaluator, /'pass'/);
});
