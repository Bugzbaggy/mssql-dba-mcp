// Standalone entry for the packaged health-report executable (appdb-sql-report.exe).
// No MCP server / Express / transport — just: load the fleet, run the report CLI, exit.
// Built into a single self-contained Windows .exe so prod SQL nodes need no Node/npm/git
// (only dbatools, already present). Usage on a node:
//   appdb-sql-report.exe --instances region2-node2 --dry-run --out C:\ProgramData\appdb-health\weekly-health.html
import { initInstances } from "./connectionManager.js";
import { runReportCli } from "./reportCli.js";

initInstances();
// slice(1): drop argv[0] (the exe); parseFlags ignores any remaining non-"--" tokens, so this
// is correct for both `node report-cli.cjs --flags` and the SEA exe `appdb-sql-report.exe --flags`.
runReportCli(process.argv.slice(1))
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[report][fatal] ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    process.exit(1);
  });
