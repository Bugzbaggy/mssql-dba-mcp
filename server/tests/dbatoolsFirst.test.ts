import { test } from "node:test";
import assert from "node:assert/strict";
import { dbatoolsFirst, withFallback } from "../src/dbatoolsFirst.ts";

test("defaults to the DMV path when the flag is unset", async () => {
  delete process.env.DBATOOLS_FIRST;
  assert.equal(dbatoolsFirst(), false);
  const r = await withFallback(async () => "dbatools", async () => "dmv");
  assert.equal(r, "dmv");
});

test("uses the dbatools path only when the flag is exactly '1'", async () => {
  process.env.DBATOOLS_FIRST = "true";
  assert.equal(dbatoolsFirst(), false);
  process.env.DBATOOLS_FIRST = "1";
  assert.equal(dbatoolsFirst(), true);
  const r = await withFallback(async () => "dbatools", async () => "dmv");
  assert.equal(r, "dbatools");
  delete process.env.DBATOOLS_FIRST;
});

test("falls back to DMV when the dbatools path throws", async () => {
  process.env.DBATOOLS_FIRST = "1";
  const r = await withFallback(
    async () => { throw new Error("worker exploded"); },
    async () => "dmv",
  );
  assert.equal(r, "dmv");
  delete process.env.DBATOOLS_FIRST;
});
