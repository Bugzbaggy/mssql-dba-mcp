// ─────────────────────────────────────────────────────────────────────────────
// sync-schema-docs — aggregate the sql-documenter JSON from every appdb-*-db
// repo into this server's bundled schema-docs/ tree, keyed by database. This is the
// SINGLE canonical semantic-layer corpus consumed by BOTH MCPs:
//   • appdb-sql-mcp serves it live (list_/search_/describe_ schema-doc tools).
//   • appdb-data-api's DB agent loads it as knowledge; its grounding generator
//     (appdb-data-api/scripts/import-schema-docs.mjs) reads this same tree.
//
//   <repo>@<default-branch>:docs/schemas/<schema>/*.json  ──►  server/schema-docs/<database>/<schema>/*.json
//
// SOURCE = each repo's LATEST DEFAULT BRANCH by default. The script `git fetch`es and
// reads docs/schemas from that repo's origin/HEAD (resolved per repo — most are
// `master`, appdb-msg-db is `dev`), so the corpus reflects each repo's merged docs
// regardless of which branch happens to be checked out locally.
//
// Run from server/:  node scripts/sync-schema-docs.mjs
//   --worktree   read each repo's checked-out working tree instead of its default branch
//                (for local iteration before your docs are merged)
//   --prune      wholesale-replace each database's bundled docs (delete first) so
//                upstream deletions propagate. Default is ADDITIVE: overlay each
//                repo's per-schema JSON, preserving bundled schemas a repo doesn't
//                (re)generate (e.g. live-generated AppDb_Analytics conv/meta/etl).
//   --dry        list what would be copied, write nothing
//   --sources P  use manifest P instead of ./schema-docs.sources.json
//                (env SCHEMA_DOCS_SOURCES does the same)
//
// The MCP server reads the bundled tree at runtime (src/schemaDocs.ts), so the docs
// ship with the build and work on the deployed HTTP server, which does NOT have the
// source repos checked out. Re-run whenever a repo's docs change on master.
// ─────────────────────────────────────────────────────────────────────────────
import { readdirSync, readFileSync, existsSync, statSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_DIR = resolve(__dirname, "..");                 // server/
const OUT_ROOT = join(SERVER_DIR, "schema-docs");

const argv = process.argv.slice(2);
const DRY = argv.includes("--dry");
const PRUNE = argv.includes("--prune");
const FROM_WORKTREE = argv.includes("--worktree");
const sourcesArg = argv[argv.indexOf("--sources") + 1];
const MANIFEST = resolve(
  SERVER_DIR,
  (argv.includes("--sources") && sourcesArg) || process.env.SCHEMA_DOCS_SOURCES || "schema-docs.sources.json"
);

function die(msg) { console.error(`✗ ${msg}`); process.exit(1); }
const isDir = (p) => { try { return statSync(p).isDirectory(); } catch { return false; } };
const git = (repo, args) => execFileSync("git", ["-C", repo, ...args], { encoding: "buffer", stdio: ["ignore", "pipe", "ignore"] });

// Resolve a repo's default branch (origin/HEAD) — NOT hardcoded, because repos differ
// (e.g. appdb-msg-db defaults to `dev`, the rest to `master`). Falls back sanely.
function defaultRef(repoDir) {
  try {
    const head = git(repoDir, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"]).toString("utf8").trim();
    if (head) return head.replace(/^refs\/remotes\//, "");        // refs/remotes/origin/dev -> origin/dev
  } catch { /* origin/HEAD not set locally — try common names */ }
  for (const r of ["origin/master", "origin/main", "origin/dev"]) {
    try { git(repoDir, ["rev-parse", "--verify", "--quiet", r]); return r; } catch { /* try next */ }
  }
  return "origin/master";
}

if (!existsSync(MANIFEST)) die(`manifest not found: ${MANIFEST}`);
let manifest;
try { manifest = JSON.parse(readFileSync(MANIFEST, "utf8")); }
catch (e) { die(`manifest is not valid JSON: ${e.message}`); }
const sources = manifest.sources ?? [];
if (!sources.length) die("manifest has no `sources`");

// Collect { schema -> [{ name, content:Buffer }] } for one repo, from origin/master
// (default) or the working tree (--worktree). Only files at docs/schemas/<schema>/<file>.json.
function collectFromWorktree(repoDir) {
  const schemasDir = join(repoDir, "docs", "schemas");
  if (!isDir(schemasDir)) return null;
  const out = {};
  for (const schema of readdirSync(schemasDir).filter((s) => isDir(join(schemasDir, s)))) {
    const files = readdirSync(join(schemasDir, schema)).filter((f) => f.toLowerCase().endsWith(".json"));
    if (files.length) out[schema] = files.map((f) => ({ name: f, content: readFileSync(join(schemasDir, schema, f)) }));
  }
  return out;
}
function collectFromMaster(repoDir) {
  try { git(repoDir, ["fetch", "--quiet", "origin"]); } catch { /* offline / no remote — fall through to whatever ref resolves */ }
  const ref = defaultRef(repoDir);
  let listing;
  try { listing = git(repoDir, ["ls-tree", "-r", "--name-only", ref, "--", "docs/schemas"]).toString("utf8"); }
  catch { return { ref, schemas: null }; } // ref or path absent
  const out = {};
  for (const p of listing.split("\n").map((x) => x.trim()).filter(Boolean)) {
    const rel = p.replace(/^docs\/schemas\//, "").split("/");
    if (rel.length !== 2 || !rel[1].toLowerCase().endsWith(".json")) continue; // skip top-level files (e.g. gaps.md)
    const [schema, name] = rel;
    let content;
    try { content = git(repoDir, ["show", `${ref}:${p}`]); } catch { continue; }
    (out[schema] ??= []).push({ name, content });
  }
  return { ref, schemas: Object.keys(out).length ? out : null };
}

console.log(`Manifest : ${MANIFEST}`);
console.log(`Source   : ${FROM_WORKTREE ? "working tree" : "each repo's default branch (origin/HEAD)"} (per repo)`);
console.log(`Output   : ${OUT_ROOT}${DRY ? "  (dry run — nothing written)" : ""}\n`);

let totalSchemas = 0, totalFiles = 0;
const empty = [];

for (const { database, repo } of sources) {
  if (!database || !repo) { console.log(`! skipping malformed source entry: ${JSON.stringify({ database, repo })}`); continue; }
  const repoDir = isAbsolute(repo) ? repo : resolve(SERVER_DIR, repo);
  if (!isDir(repoDir)) { empty.push({ database, reason: `repo path not found: ${repoDir}` }); console.log(`▸ ${database}: repo path not found (${repoDir})`); continue; }

  let collected, srcLabel;
  if (FROM_WORKTREE) { collected = collectFromWorktree(repoDir); srcLabel = "working tree"; }
  else { const r = collectFromMaster(repoDir); collected = r.schemas; srcLabel = r.ref; }
  if (!collected) {
    empty.push({ database, reason: FROM_WORKTREE ? "no docs/schemas in working tree" : `no docs/schemas on ${srcLabel} (merge the sql-documenter PR to that branch, or use --worktree)` });
    console.log(`▸ ${database}: 0 schemas — ${FROM_WORKTREE ? "docs/schemas missing (run sql-documenter)" : `nothing on ${srcLabel}`}`);
    continue;
  }

  const dbOut = join(OUT_ROOT, database);
  const preExisting = isDir(dbOut) ? readdirSync(dbOut).filter((s) => isDir(join(dbOut, s))) : [];
  if (PRUNE && !DRY && existsSync(dbOut)) rmSync(dbOut, { recursive: true, force: true });

  let dbFiles = 0;
  const schemaNames = [];
  for (const [schema, files] of Object.entries(collected)) {
    const destDir = join(dbOut, schema);
    if (!DRY) mkdirSync(destDir, { recursive: true });
    for (const f of files) {
      if (!DRY) writeFileSync(join(destDir, f.name), f.content);   // overlay: refresh files, keep the rest
      dbFiles++;
    }
    schemaNames.push(schema);
  }
  totalSchemas += schemaNames.length;
  totalFiles += dbFiles;

  const preserved = PRUNE ? [] : preExisting.filter((s) => !schemaNames.includes(s));
  console.log(`▸ ${database}: ${PRUNE ? "replaced" : "merged"} ${schemaNames.length} schema(s) from ${srcLabel} [${schemaNames.join(", ")}], ${dbFiles} file(s)`
    + (preserved.length ? `; preserved ${preserved.length} bundled-only [${preserved.join(", ")}]` : ""));
}

console.log(`\n${DRY ? "Would sync" : "Synced"} ${totalSchemas} schema(s), ${totalFiles} JSON file(s) across ${sources.length} source repo(s).`);
if (empty.length) {
  console.log(`\nNot synced (merge the sql-documenter docs to master, or run with --worktree):`);
  for (const e of empty) console.log(`  - ${e.database}: ${e.reason}`);
}
