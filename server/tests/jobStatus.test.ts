import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { jobStatusResult, JOB_STATUS_MSDB_SQL } from "../src/tools.js";

// get_job_status uses dbatools (SMO), and SMO hands a non-sysadmin an EMPTY job list with no error,
// even in SQLAgentReaderRole (measured against SQL Server 2022 with dbatools 2.7.2). An empty
// answer is therefore only evidence once msdb itself has been asked.

test("dbatools rows are returned as they are", () => {
  assert.deepEqual(jobStatusResult([{ Name: "j" }], { rows: [] }), { job_status: [{ Name: "j" }] });
});

test("an empty SMO list is checked against msdb, and msdb's rows are returned with their source", () => {
  const r = jobStatusResult([], { rows: [{ job_name: "nightly", current_state: "FAILED" }] });
  assert.equal(r.source, "msdb");
  assert.deepEqual(r.job_status, [{ job_name: "nightly", current_state: "FAILED" }]);
  assert.match(String(r.note), /SMO shows a non-sysadmin no jobs/);
});

test("only an empty msdb is reported as 'no jobs'; an unreadable msdb is 'could not read'", () => {
  assert.match(String(jobStatusResult([], { rows: [] }).note), /No Agent jobs on this instance/);
  const cnr = jobStatusResult([], { error: "The SELECT permission was denied on the object 'sysjobs'" });
  assert.equal(cnr.could_not_read, true);
  assert.match(String(cnr.note), /NOT evidence that the instance has no Agent jobs/);
});

test("the msdb fallback reads only the tables deploy/01 grants, and bounds itself", () => {
  const tables = [...JOB_STATUS_MSDB_SQL.matchAll(/msdb\.dbo\.(\w+)/g)].map((m) => m[1]);
  const grants = readFileSync(new URL("../../deploy/01-svc_sqldiag-login-and-grants.sql", import.meta.url), "utf8");
  for (const t of new Set(tables)) {
    assert.match(grants, new RegExp(`GRANT (SELECT|EXECUTE) ON OBJECT::dbo\\.${t}\\s`), `deploy/01 must grant dbo.${t}`);
  }
  assert.match(JOB_STATUS_MSDB_SQL, /SELECT TOP \(500\)/, "carries its own TOP, so the row cap cannot cut it silently");
});
