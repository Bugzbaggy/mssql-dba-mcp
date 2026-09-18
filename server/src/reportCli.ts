// Shared report-CLI logic, used by BOTH the MCP server's `report` subcommand (index.ts)
// and the standalone packaged executable (report-cli.ts). One implementation → the
// scheduled report stays byte-for-byte the interactive run_health_check (same runHealthReport
// → generateHtmlReport). In the on-server job the exe runs `report … --dry-run --out <file>`
// (Windows auth, no creds); a T-SQL Agent step then emails the file. --recipients (email via
// Database Mail) is also supported for hosts that can reach the fleet.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { listInstances, sendDbMail } from "./connectionManager.js";
import { runHealthReport } from "./dbatools.js";

const log = (m: string): void => console.error(m);

export function parseFlags(argv: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const k = a.slice(2);
    const eq = k.indexOf("=");
    if (eq >= 0) o[k.slice(0, eq)] = k.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) o[k] = argv[++i];
    else o[k] = "true";
  }
  return o;
}

// argv = full process.argv; the report args start after the `report` token (or at [2] for the exe).
export async function runReportCli(argv: string[]): Promise<void> {
  const f = parseFlags(argv);
  const dryRun = f["dry-run"] === "true" || f["dry-run"] === "1";
  const recipients = f.recipients;
  if (!recipients && !dryRun) throw new Error("report mode requires --recipients <email> (or --dry-run to write the HTML to a file instead of emailing)");

  let targets = listInstances().filter((i) => i.kind !== "witness");
  if (f.region) targets = targets.filter((i) => (i.region ?? "").toLowerCase() === f.region.toLowerCase());
  if (f.instances) { const set = new Set(f.instances.split(",")); targets = targets.filter((i) => set.has(i.name)); }
  if (!targets.length) throw new Error("report mode: no matching instances (check --region / --instances against list_instances)");

  const useSql = (f.auth ?? ((process.env.SQL_USER && process.env.SQL_PASSWORD) ? "sql" : "windows")) === "sql";
  const generatedAt = new Date().toISOString();
  log(`[report] health check on ${targets.length} instance(s): ${targets.map((t) => t.name).join(", ")} (auth=${useSql ? "sql" : "windows"})`);
  const { reports, html } = await runHealthReport(targets, { useSql, generatedAt });
  if (!reports.length) throw new Error("report mode: no instance produced results (see [report] log lines above)");

  const worst = reports.reduce<string>((w, r) =>
    r.status_counts.Fail > 0 ? "CRITICAL" : (r.status_counts.Attention > 0 && w !== "CRITICAL" ? "WARNING" : w), "OK");
  const label = f.region ?? targets.map((t) => t.name).join(",");
  const subject = `[${worst}] SQL Health — ${label} (${generatedAt.slice(0, 10)})`;

  if (dryRun) {
    const out = f.out ?? join(process.env.HEALTHCHECK_REPORT_DIR ?? tmpdir(), `sql-health-${label.replace(/[^A-Za-z0-9_-]/g, "_")}-${generatedAt.replace(/[:.]/g, "-")}.html`);
    // Write UTF-16LE with a BOM: the on-server job reads this back with
    // OPENROWSET(... SINGLE_NCLOB), which requires a UTF-16 (widechar) file.
    // Plain UTF-8 fails step 2 with Error 4809. The BOM (FF FE) is the marker.
    writeFileSync(out, Buffer.from("\uFEFF" + html, "utf16le"));
    log(`[report] DRY RUN — wrote HTML to ${out} (subject would be "${subject}"); not emailed.`);
    return;
  }

  const profile = f.profile ?? "AppDb Email Profile";
  const mailInstance = f["mail-instance"] ?? (f.region ? `${f.region}-primary` : targets[0].name);
  await sendDbMail(mailInstance, { profileName: profile, recipients, subject, htmlBody: html, importance: worst === "CRITICAL" ? "High" : "Normal" });
  log(`[report] sent "${subject}" to ${recipients} via ${mailInstance} (Database Mail profile "${profile}")`);
}
