import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { BASE_HOST_DLL_WATCHLIST, HOST_DLL_WATCHLIST, parseHostDllWatchlist, hostDllProbe } from "../src/dbatools.js";

// get_host_dll_versions compares module versions between a crashing node and a healthy peer. The
// built-in list is Microsoft-only; which third-party modules get injected into sqlservr.exe (a
// security agent, an ODBC driver) is a fact about one estate, so those are site entries.

test("the built-in watchlist names only Windows core, the VC++ runtime and SQL Server binaries", () => {
  assert.ok(BASE_HOST_DLL_WATCHLIST.length >= 10);
  for (const e of BASE_HOST_DLL_WATCHLIST) {
    assert.match(e.path, /^(Windows\\System32\\|Program Files\\Microsoft SQL Server\\)/, `not a Microsoft path: ${e.path}`);
    assert.match(e.label, /^(Windows core|VC\+\+ runtime|SQL Server binary)$/);
  }
  assert.ok(BASE_HOST_DLL_WATCHLIST.some((e) => e.path === "Windows\\System32\\ntdll.dll"), "ntdll is also the reachability sentinel");
  assert.deepEqual(HOST_DLL_WATCHLIST, BASE_HOST_DLL_WATCHLIST, "with nothing configured there are no site entries");
});

test("site entries: relative paths only, a label each, nothing that could break the PowerShell literal", () => {
  const got = parseHostDllWatchlist(JSON.stringify([
    { path: "Program Files\\ExampleVendor\\agent.dll", label: "security agent" },
    { path: "\\Program Files\\ExampleDriver\\lib\\*.dll" },
    { path: "C:\\Windows\\evil.dll", label: "x" },
    { path: "Program Files\\..\\Windows\\x.dll", label: "x" },
    { path: "Program Files\\it's.dll", label: "x" },
    { label: "no path" },
  ]));
  assert.deepEqual(got, [
    { path: "Program Files\\ExampleVendor\\agent.dll", label: "security agent" },
    { path: "Program Files\\ExampleDriver\\lib\\*.dll", label: "site entry" },
  ]);
  assert.deepEqual(parseHostDllWatchlist("not json"), []);
  assert.deepEqual(parseHostDllWatchlist('{"path":"x"}'), [], "an object is not a list");
});

test("the probe list is de-duplicated, caller paths are validated, and every row can carry a label", () => {
  const site = [...BASE_HOST_DLL_WATCHLIST, { path: "Program Files\\ExampleVendor\\agent.dll", label: "security agent" }];
  const p = hostDllProbe(true, ["windows\\system32\\NTDLL.dll", "Program Files\\App\\app.dll"], site);
  assert.equal(p.paths.filter((x) => x.toLowerCase().endsWith("ntdll.dll")).length, 1, "a repeated key would not parse as a hash literal");
  assert.ok(p.paths.includes("Program Files\\App\\app.dll"));
  assert.match(p.psLabels, /'Program Files\\ExampleVendor\\agent\.dll'='security agent'/);
  assert.match(p.psLabels, /'Program Files\\App\\app\.dll'='caller-supplied'/);
  assert.deepEqual(hostDllProbe(false, [], site).paths, []);
  assert.throws(() => hostDllProbe(true, ["..\\x.dll"]), /'\.\.'/);
  assert.throws(() => hostDllProbe(true, ["D:\\x.dll"]), /Absolute drive path/);
  assert.throws(() => hostDllProbe(true, ["\\\\host\\c$\\x.dll"]), /UNC path/);
});

const shell = ["pwsh", "powershell"].find((s) => spawnSync(s, ["-NoProfile", "-Command", "exit 0"]).status === 0);
test("the emitted array and label map evaluate in PowerShell", { skip: !shell && "no PowerShell on this host" }, () => {
  const p = hostDllProbe(true, ["Program Files\\App\\app.dll"], [...BASE_HOST_DLL_WATCHLIST,
    { path: "Program Files\\ExampleVendor\\agent.dll", label: "security agent" }]);
  const script = `$patterns = ${p.psArray}; $labels = ${p.psLabels}; ` +
    "Write-Output $patterns.Count; foreach ($rel in $patterns) { Write-Output ($rel + '|' + $labels[$rel]) }";
  const r = spawnSync(shell!, ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim().split(/\r?\n/);
  assert.equal(Number(out[0]), p.paths.length);
  assert.ok(out.includes("Program Files\\ExampleVendor\\agent.dll|security agent"));
  assert.ok(out.includes("Program Files\\App\\app.dll|caller-supplied"));
  assert.ok(out.includes("Windows\\System32\\ntdll.dll|Windows core"));
});
