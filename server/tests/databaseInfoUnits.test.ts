import { test } from "node:test";
import assert from "node:assert/strict";
import { toDatabaseInfoRow } from "../src/tools.ts";

// get_database_info: SMO reports Database.Size in MEGABYTES and Database.SpaceAvailable in
// KILOBYTES (confirmed against dbatools' own Get-DbaDatabase source, which aliases the raw
// Size property to "SizeMB" in its default view, and Microsoft's SMO Database class docs,
// which document SpaceAvailable in KB). toDatabaseInfoRow must relabel both into the same
// unit (MB) so an agent reading the two adjacent columns can compare them directly instead
// of being silently off by 1024x.
test("toDatabaseInfoRow converts SpaceAvailable (KB) to MB and relabels both size fields", () => {
  const row = { Name: "AppCatalog", Size: 2048, SpaceAvailable: 10240, Owner: "sa" };
  const out = toDatabaseInfoRow(row);
  assert.equal(out.SizeMB, 2048); // Size is already MB - value carries over unchanged
  assert.equal(out.SpaceAvailableMB, 10); // 10240 KB / 1024 = 10 MB
  assert.equal(out.Name, "AppCatalog");
  assert.equal(out.Owner, "sa");
  assert.equal("Size" in out, false);
  assert.equal("SpaceAvailable" in out, false);
});

test("toDatabaseInfoRow rounds SpaceAvailableMB to 2 decimal places", () => {
  const out = toDatabaseInfoRow({ Size: 100, SpaceAvailable: 1000 });
  // 1000 KB / 1024 = 0.9765625 MB -> rounded to 0.98
  assert.equal(out.SpaceAvailableMB, 0.98);
});

test("toDatabaseInfoRow passes through a non-numeric SpaceAvailable unchanged rather than throwing", () => {
  const out = toDatabaseInfoRow({ Size: 100, SpaceAvailable: null });
  assert.equal(out.SpaceAvailableMB, null);
});
