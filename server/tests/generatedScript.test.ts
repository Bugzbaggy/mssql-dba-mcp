/**
 * Guards on the PowerShell the generator EMITS, not on the TypeScript that emits it.
 *
 * Every other test in this suite exercises the TypeScript side — catalog shape, grading,
 * details, remediation, HTML. None of them execute or even read the generated script, and
 * two real defects lived in exactly that gap until they were found by running the emitted
 * block by hand:
 *
 *   1. `Invoke-SqlAssessment -ServerInstance <x>` — that parameter DOES NOT EXIST. Measured
 *      against SqlServer 22.1.1 the cmdlet takes only Check, InputObject, Configuration,
 *      MinSeverity, FlattenOutput. The check would have failed on every node, every week,
 *      with "A parameter cannot be found that matches parameter name 'ServerInstance'".
 *
 *   2. `@($json | ConvertFrom-Json)` — under Windows PowerShell 5.1, which is what
 *      powershell.exe is and what the scheduled report runs, ConvertFrom-Json does NOT
 *      enumerate a JSON array through a pipeline. Measured:
 *        @($j | ConvertFrom-Json)           -> count=1, [0].CheckId='A B C', high=0
 *        $v = $j | ConvertFrom-Json; @($v)  -> count=3, [0].CheckId='A',     high=1
 *      With the pipeline form the grading expression saw ONE row whose .Severity was the
 *      whole array, matched nothing, and reported 'pass' no matter how many Critical
 *      findings came back. pwsh 7 gets it right, so an interactive test never shows it, and
 *      a single-finding result masks it because a one-element array flattens identically.
 *
 * Both are invisible to a TypeScript assertion about the catalog and both produce a
 * CONFIDENT WRONG ANSWER rather than an error, which is the failure mode this report exists
 * to avoid. So: assert on the emitted text.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildHealthCheckScript, CATALOG } from "../src/dbatools.js";

const cfg = { name: "region1-node2", host: "10.0.9.9", port: 1433, database: "AppCatalog" } as Parameters<typeof buildHealthCheckScript>[0];
const winScript = buildHealthCheckScript(cfg, false, 25);
const sqlScript = buildHealthCheckScript(cfg, true, 25);
const HERE_OPEN = "$__sacmd = @" + "'";

/** The SA child block: from the here-string opener to the end of that check's $d assignment. */
function saBlock(script: string): string {
  const i = script.indexOf(HERE_OPEN);
  assert.notEqual(i, -1, "the SQL Assessment child block is not present in the generated script");
  const j = script.indexOf("\n  $__shown", i);
  return script.slice(i, j);
}

test("Invoke-SqlAssessment is called with -InputObject, never the parameter that does not exist", () => {
  const b = saBlock(winScript);
  assert.match(b, /Invoke-SqlAssessment -InputObject \$srv\b/,
    "the assessment must be handed an SMO Server on -InputObject");
  assert.doesNotMatch(b, /Invoke-SqlAssessment[^\n]*-ServerInstance/,
    "Invoke-SqlAssessment has no -ServerInstance parameter — this fails the check outright");
  assert.match(b, /Get-SqlInstance -ServerInstance /,
    "the SMO Server has to come from somewhere");
});

test("no pipeline-form ConvertFrom-Json anywhere in the generated script", () => {
  // The whole script, not just the SA block: this trap silently reduces ANY parsed array to
  // one un-enumerated element on 5.1, so it must not appear at all.
  for (const [tag, script] of [["win", winScript], ["sql", sqlScript]] as const) {
    const bad = script.split("\n").filter((l) => /@\(\s*\$[A-Za-z_][\w:]*\s*\|\s*ConvertFrom-Json/.test(l));
    assert.deepEqual(bad, [], `${tag}: assign before wrapping — @($x | ConvertFrom-Json) does not enumerate on PS 5.1`);
  }
});

test("the child is invoked with -EncodedCommand, which -Command's quote stripping breaks", () => {
  const b = saBlock(winScript);
  // Measured: a double-quoted payload came back as '[null]' under -Command and intact under
  // -EncodedCommand. The current body happens to use single quotes only, which is luck.
  assert.match(b, /-EncodedCommand \$__sab64/, "use base64 UTF-16LE, not -Command");
  assert.doesNotMatch(b, /powershell\.exe[^\n]*-Command \$__sacmd/, "-Command strips double quotes from the body");
  assert.match(b, /\[Convert\]::ToBase64String\(\[Text\.Encoding\]::Unicode\.GetBytes\(\$__sacmd\)\)/);
});

test("cmd.exe variable syntax never reaches a PowerShell here-string", () => {
  // %COMPUTERNAME% is expanded by nothing on this path; a single-quoted here-string expands
  // nothing at all, so it arrived at the child as a literal instance name. Measured: a child
  // printed "pct=[%COMPUTERNAME%] env=[WORKSTATION01]".
  // Scope this to the SA child block: the SQL text elsewhere legitimately contains T-SQL LIKE
  // patterns such as '%DAC%' and '%OFFLINE%', which are not variable references at all.
  assert.doesNotMatch(saBlock(winScript), /%[A-Z_]+%/, "%VAR% is cmd.exe syntax and is never expanded here");
  // Whatever the mode, the instance argument must be a PowerShell EXPRESSION — an $env: read
  // or a quoted literal — because the here-string hands it to the child verbatim.
  assert.match(saBlock(winScript), /Get-SqlInstance -ServerInstance (\$env:COMPUTERNAME|'[^']+')(\s|$)/m);
});

test("the DEPLOYED on-node mode emits $env:COMPUTERNAME, not a cmd.exe token", () => {
  // HEALTHCHECK_OS_LOCAL is read once at module load, so it cannot be flipped in-process —
  // and it gates precisely the branch that shipped the bug (the weekly job runs per node
  // against itself with HEALTHCHECK_OS_LOCAL=1). Generate that variant in a child process.
  const src = [
    "import { buildHealthCheckScript } from '../src/dbatools.js';",
    "const cfg = { name: 'region1-node2', host: '10.0.9.9', port: 1433, database: 'AppCatalog' };",
    "process.stdout.write(buildHealthCheckScript(cfg, false, 25));",
  ].join("\n");
  const file = new URL("./.on-node-gen.tmp.mts", import.meta.url);
  writeFileSync(file, src, "utf8");
  try {
    const out = execFileSync(process.execPath, ["--import", "tsx", fileURLToPath(file)], {
      encoding: "utf8", env: { ...process.env, HEALTHCHECK_OS_LOCAL: "1" }, maxBuffer: 32 * 1024 * 1024,
    });
    const b = saBlock(out);
    assert.match(b, /Get-SqlInstance -ServerInstance \$env:COMPUTERNAME/,
      "on-node the child must resolve the instance itself, via $env: which survives the here-string");
    assert.doesNotMatch(b, /%[A-Z_]+%/, "%COMPUTERNAME% is cmd.exe syntax and is never expanded on this path");
    assert.doesNotMatch(b, /Invoke-SqlAssessment[^\n]*-ServerInstance/);
  } finally {
    rmSync(file, { force: true });
  }
});

test("sentinel rows are pscustomobject, because ConvertTo-PlainRows cannot read a hashtable", () => {
  // ConvertTo-PlainRows walks $row.PSObject.Properties; on a Hashtable that yields
  // Keys/Values/Count instead of the entry, so a bare @{} sentinel renders as nonsense.
  const b = saBlock(winScript);
  const parentSentinels = b.split("\n").filter((l) => /__sa_error =/.test(l) && !/^\s*ConvertTo-Json/.test(l));
  assert.ok(parentSentinels.length >= 2, "expected the parent-side failure sentinels");
  for (const l of parentSentinels)
    assert.match(l, /@\(\[pscustomobject\]@\{/, `parent sentinel must be a pscustomobject: ${l.trim().slice(0, 90)}`);
});

test("a clean assessment is a pass, not an error and not Info", () => {
  const b = saBlock(winScript);
  // The child prints the literal '[]' when it found nothing. Any "does this look like JSON?"
  // heuristic rejects that, which would report a healthy node as a collection failure.
  assert.match(b, /elseif \(\$__sajson -eq '\[\]'\)/, "the empty-result case must be named explicitly");
  assert.doesNotMatch(b, /-notlike '\*\{\*'/, "a '{' heuristic misclassifies the clean '[]' result");
});

test("the assessment is skipped under SQL auth so no password reaches a child command line", () => {
  assert.ok(!sqlScript.includes(HERE_OPEN), "SQL auth must not invoke the assessment child at all");
  assert.ok(winScript.includes(HERE_OPEN), "Windows auth must invoke it");
});

test("every here-string terminator sits at column 0, or the script does not parse", () => {
  for (const [tag, script] of [["win", winScript], ["sql", sqlScript]] as const) {
    const lines = script.split("\n");
    let open = 0;
    lines.forEach((l, n) => {
      if (/@['"]\s*$/.test(l)) open++;
      else if (/^['"]@/.test(l)) open--;
      else assert.doesNotMatch(l, /^\s+['"]@\s*$/, `${tag}:${n + 1}: here-string terminator is indented`);
    });
    assert.equal(open, 0, `${tag}: unbalanced here-strings (${open})`);
  }
});

test("every act-now label is a real catalog label", () => {
  // The triage list is matched by exact string. A typo or a renamed check silently demotes a
  // data-loss finding to "this week" — the failure is invisible because the report still
  // renders and still says Fail.
  const labels = new Set(CATALOG.map((c) => c[1] as string));
  const src = readFileSync(new URL("../src/dbatools.ts", import.meta.url), "utf8");
  const block = /const ACT_NOW_LABELS = new Set<string>\(\[([\s\S]*?)\]\);/.exec(src);
  assert.ok(block, "ACT_NOW_LABELS not found");
  const names = [...block[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  assert.ok(names.length >= 8, `expected the act-now list, got ${names.length}`);
  for (const n of names) assert.ok(labels.has(n), `act-now label "${n}" is not a catalog label`);
});

test("every describe() case is reachable from the key describe() actually computes", () => {
  // describe() keys on the dbatools COMMAND, except for a small set keyed by LABEL. A case
  // written as a label whose command is NOT in that set can never match — and the failure is
  // silent: the switch falls through to the generic "no per-row summary rule" text. In practice
  // a Fail carrying several assessment findings, one of them High severity, described itself as
  // having nothing to say.
  const src = readFileSync(new URL("../src/dbatools.ts", import.meta.url), "utf8");
  const kset = /const LABEL_KEYED = new Set\(\[([^\]]*)\]\)/.exec(src);
  assert.ok(kset, "LABEL_KEYED not found in describe()");
  const labelKeyed = new Set([...kset[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]));

  // Bound the switch to describe()'s body: from its signature to the next top-level function.
  const start = src.indexOf("function describe(c: RawCheck): string | null {");
  assert.notEqual(start, -1);
  const end = src.indexOf("\nfunction ", start + 10);
  const body = src.slice(start, end > 0 ? end : undefined);

  const commands = new Map(CATALOG.map((c) => [c[2] as string, c]));
  const labels = new Map(CATALOG.map((c) => [c[1] as string, c]));
  const unreachable: string[] = [];
  for (const m of body.matchAll(/^\s{4}case "((?:[^"\\]|\\.)*)":/gm)) {
    const key = m[1];
    const byCommand = commands.get(key);
    if (byCommand && !labelKeyed.has(byCommand[2] as string)) continue;   // keyed by command
    const byLabel = labels.get(key);
    if (byLabel && labelKeyed.has(byLabel[2] as string)) continue;        // keyed by label
    if (byLabel && !labelKeyed.has(byLabel[2] as string))
      unreachable.push(`"${key}" is a LABEL but its command ${byLabel[2]} is not LABEL_KEYED`);
    else if (!byCommand && !byLabel)
      unreachable.push(`"${key}" matches no catalog command or label`);
  }
  assert.deepEqual(unreachable, [], "describe() cases that can never match");
});

test("Windows paths in emitted strings keep their backslashes", () => {
  // In a TS double-quoted string \P \W \M \S are not valid escapes, so a single backslash is
  // silently DROPPED. Measured: the SqlServer module diagnostic shipped as
  // 'C:Program FilesWindowsPowerShellModulesSqlServer' — a path matching nothing, so the
  // query returned zero rows and read as "the module is not installed". Nothing throws.
  const src = readFileSync(new URL("../src/dbatools.ts", import.meta.url), "utf8");
  const offenders: string[] = [];
  src.split("\n").forEach((line, i) => {
    if (/\/\//.test(line.trim().slice(0, 2))) return;          // skip comment lines
    if (/C:\\(?!\\)/.test(line)) offenders.push(`${i + 1}: ${line.trim().slice(0, 110)}`);
    // A lone backslash between single quotes. In a TS double-quoted string \' is an escaped
    // QUOTE, so "CHARINDEX('\', ...)" swallowed the closing quote and emitted CHARINDEX('', ...)
    // — a path separator that matches nothing, so the directory never resolved and the file
    // enumeration returned zero rows. The correct source form is '\\'.
    if (line.includes("'" + String.fromCharCode(92) + "'"))
      offenders.push(`${i + 1}: lone backslash in quotes — ${line.trim().slice(0, 100)}`);
  });
  assert.deepEqual(offenders, [], "single-backslash C:\\ path in a TS string — the backslash is dropped");
});

test("the connection arguments that make the fleet reachable are all present", () => {
  // Every one of these is load-bearing, and dropping any of them fails in a way that looks like
  // a broken NODE rather than a broken connection string. Measured by reproducing the connection
  // without them:
  //   -Database        omitted -> a node with a Failover Partner in its connection fails outright with
  //                    "Use of key 'Failover Partner' requires the key 'Initial Catalog' to be present"
  //                    (SqlConnectionStringBuilder validation, nothing to do with the node being unreachable).
  //   -ApplicationIntent ReadOnly omitted -> the AG does not route to a readable replica, SMO marks
  //                    the non-readable copies inaccessible, and Get-DbaLastGoodCheckDb aborts the
  //                    WHOLE check with "The database <x> is not accessible. Skipping database."
  //                    That reproduces on any replica holding a non-readable copy and looks exactly
  //                    like a fleet-wide coverage hole. It is not.
  // With all of them, every node connects and both checks return rows.
  for (const [tag, script] of [["win", winScript], ["sql", sqlScript]] as const) {
    // The connect line lives in New-HcServer, so a reconnect builds exactly the same connection.
    const m = /\n {2}\$s = Connect-DbaInstance ([^\n]+)/.exec(script);
    assert.ok(m, `${tag}: no Connect-DbaInstance line`);
    const args = m[1];
    assert.match(args, /-Database '/, `${tag}: -Database is required or a node with a Failover Partner cannot connect at all`);
    assert.match(args, /-ApplicationIntent ReadOnly/, `${tag}: without it, AG replicas report databases inaccessible and whole checks abort`);
    assert.match(args, /-TrustServerCertificate/, `${tag}: instance certs are often internal-CA/self-signed`);
    assert.match(args, /-ConnectTimeout \d+/, `${tag}: an unbounded connect can hang the whole run`);
  }
  // Under SQL auth the credential must come from the child-process environment, never inline.
  assert.match(sqlScript, /\n {2}\$s = Connect-DbaInstance [^\n]*-SqlCredential \$__cred/);
  assert.match(sqlScript, /ConvertTo-SecureString \$env:APPDB_HC_SQL_PASSWORD/);
  assert.doesNotMatch(sqlScript, /-SqlCredential\s+\(New-Object[^\n]*'[^']{8,}'/, "no literal password in the script body");
});

test("run_health_check can target the whole fleet, and never a witness host", () => {
  // Witness hosts run no SQL Server. A region sweep used to include e.g. region1-witness and bank a
  // guaranteed failure into the fleet report — a "could not look" that reads like a sick node.
  // reportCli already filtered them; the MCP tool did not.
  const src = readFileSync(new URL("../src/dbatools.ts", import.meta.url), "utf8");
  const start = src.indexOf('"run_health_check"');
  assert.notEqual(start, -1);
  // Wide enough to reach the HANDLER, not just the tool description and the zod schema —
  // the description alone is ~1,500 characters.
  const body = src.slice(start, start + 16000);

  assert.match(body, /kind \?\? "sql"\) === "sql"/, "witness hosts must be excluded before any other filtering");
  assert.match(body, /wantAll/, "region:'all' must be supported");
  assert.match(body, /instances\?\.length/, "an explicit instance list must be supported");
  assert.match(body, /concurrency/, "a fleet sweep needs bounded concurrency to finish in sensible wall-clock");

  // The pool must be bounded, not an unbounded Promise.all over every instance: each slot is a
  // separate PowerShell process loading dbatools.
  assert.match(body, /Math\.min\(concurrency \?\? \d+, targets\.length\)/);
  assert.doesNotMatch(body, /await Promise\.all\(targets\.map\(/, "that would spawn one process per instance at once");
  // Results are written back by index so report order does not depend on which node finishes first.
  assert.match(body, /ordered\[idx\]/);
});

test("the report CLI also excludes witness hosts", () => {
  const cli = readFileSync(new URL("../src/reportCli.ts", import.meta.url), "utf8");
  assert.match(cli, /kind !== "witness"/, "the weekly job must not try to health-check a file-share witness");
});
