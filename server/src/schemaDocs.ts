// ─────────────────────────────────────────────────────────────────────────────
// Schema-doc semantic layer.
//
// The sql-documenter skill (run inside each appdb-*-db repo) emits structured
// JSON under that repo's docs/schemas/<schema>/*.json. The sync:docs script copies
// those files, keyed by DATABASE, into this server's bundled schema-docs/ directory:
//
//   schema-docs/<database>/<schema>/{overview,tables,procedures,views,functions,synonyms}.json
//
// This module loads that tree (read-only, no DB connection) and serves it to the
// agent so the ops/eng/dba profiles know column meanings, enum decodings, foreign
// keys, procedure usage and access roles BEFORE writing a query. It is the semantic
// layer over the live SQL the rest of the server runs.
//
// Path resolution: SCHEMA_DOCS_DIR overrides; otherwise the bundle ships the docs
// next to dist/ (the esbuild output is CJS, so __dirname is dist/ at runtime).
// ─────────────────────────────────────────────────────────────────────────────
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

// Object-type doc files the sql-documenter skill can emit, mapped to the array key
// each one carries at its top level (tables.json => { tables: [...] }, etc.).
const OBJECT_FILES: Array<{ file: string; key: string; objectType: string }> = [
  { file: "tables.json", key: "tables", objectType: "table" },
  { file: "procedures.json", key: "procedures", objectType: "procedure" },
  { file: "views.json", key: "views", objectType: "view" },
  { file: "functions.json", key: "functions", objectType: "function" },
  { file: "synonyms.json", key: "synonyms", objectType: "synonym" },
];

function defaultDocsDir(): string {
  // Production build is a CJS esbuild bundle => __dirname is dist/, docs are ../schema-docs.
  // `typeof` guard keeps this safe if ever loaded as ESM (where __dirname is absent).
  const here = typeof __dirname !== "undefined" ? __dirname : process.cwd();
  return join(here, "..", "schema-docs");
}

export function docsRoot(): string {
  const override = process.env.SCHEMA_DOCS_DIR?.trim();
  return override ? override : defaultDocsDir();
}

// ── Caches. Docs are static for the life of the process, so parse once. ──
const fileCache = new Map<string, unknown>();

function readJson(path: string): any | null {
  if (fileCache.has(path)) return fileCache.get(path) as any;
  let parsed: any = null;
  try {
    if (existsSync(path)) parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    parsed = null; // a malformed doc file must not crash a tool call
  }
  fileCache.set(path, parsed);
  return parsed;
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function listDir(p: string): string[] {
  try {
    return readdirSync(p);
  } catch {
    return [];
  }
}

// Database / schema folder names are matched case-insensitively so the agent can
// pass "appdb_analytics" / "AppDb_Analytics" / "bi" interchangeably.
function resolveDir(parent: string, name: string): string | null {
  if (!name) return null;
  const direct = join(parent, name);
  if (isDir(direct)) return direct;
  const lower = name.toLowerCase();
  const hit = listDir(parent).find((d) => d.toLowerCase() === lower && isDir(join(parent, d)));
  return hit ? join(parent, hit) : null;
}

export interface SchemaSummary {
  database: string;
  schema: string;
  fullName: string | null;
  purpose: string | null;
  objectCount: Record<string, number> | null;
  // accessProfiles surfaces which MCP profiles (ops/eng) can read the schema, so the
  // discovery tool can foreground what the calling profile is actually able to SELECT.
  accessProfiles: unknown | null;
}

// Walk schema-docs/<database>/<schema>/overview.json for every documented schema.
export function listSchemaDocs(): SchemaSummary[] {
  const root = docsRoot();
  const out: SchemaSummary[] = [];
  for (const db of listDir(root)) {
    const dbDir = join(root, db);
    if (!isDir(dbDir)) continue;
    for (const schema of listDir(dbDir)) {
      const schemaDir = join(dbDir, schema);
      if (!isDir(schemaDir)) continue;
      const ov = readJson(join(schemaDir, "overview.json"));
      out.push({
        database: db,
        schema,
        fullName: ov?.fullName ?? null,
        purpose: ov?.purpose ?? null,
        objectCount: ov?.objectCount ?? null,
        accessProfiles: ov?.accessProfiles ?? null,
      });
    }
  }
  return out.sort((a, b) => a.database.localeCompare(b.database) || a.schema.localeCompare(b.schema));
}

function schemaDir(database: string, schema: string): string | null {
  const dbDir = resolveDir(docsRoot(), database);
  if (!dbDir) return null;
  return resolveDir(dbDir, schema);
}

// Full overview.json for one (database, schema), or null if not documented.
export function describeSchema(database: string, schema: string): any | null {
  const dir = schemaDir(database, schema);
  if (!dir) return null;
  return readJson(join(dir, "overview.json"));
}

// Find a named object (table/view/proc/function/synonym) within a schema and return
// its full doc plus the resolved object type. Name match is case-insensitive.
export function describeDocObject(database: string, schema: string, name: string): any | null {
  const dir = schemaDir(database, schema);
  if (!dir) return null;
  const want = name.toLowerCase();
  for (const { file, key, objectType } of OBJECT_FILES) {
    const doc = readJson(join(dir, file));
    const arr: any[] = doc?.[key] ?? [];
    const hit = arr.find((o) => typeof o?.name === "string" && o.name.toLowerCase() === want);
    if (hit) return { database, schema, objectType, ...hit };
  }
  return null;
}

export interface SearchHit {
  database: string;
  schema: string;
  objectType: string;
  object: string;
  matchedOn: string[];
}

// Free-text search across every documented object: object names, descriptions,
// column names/descriptions, and enum decodings. Lets the agent answer "where is
// conversion rate stored?" without knowing the database or schema up front.
export function searchSchemaDocs(term: string, database?: string, limit = 40): SearchHit[] {
  const needle = term.trim().toLowerCase();
  if (!needle) return [];
  const root = docsRoot();
  const hits: SearchHit[] = [];

  const dbDirs = database
    ? [resolveDir(root, database)].filter((d): d is string => d !== null)
    : listDir(root).map((d) => join(root, d)).filter(isDir);

  for (const dbDir of dbDirs) {
    const db = dbDir.split(/[\\/]/).pop() as string;
    for (const schema of listDir(dbDir)) {
      const dir = join(dbDir, schema);
      if (!isDir(dir)) continue;
      for (const { file, key, objectType } of OBJECT_FILES) {
        const doc = readJson(join(dir, file));
        const arr: any[] = doc?.[key] ?? [];
        for (const o of arr) {
          const matchedOn: string[] = [];
          if (typeof o?.name === "string" && o.name.toLowerCase().includes(needle)) matchedOn.push("name");
          if (typeof o?.description === "string" && o.description.toLowerCase().includes(needle)) matchedOn.push("description");
          for (const col of o?.columns ?? []) {
            if (typeof col?.name === "string" && col.name.toLowerCase().includes(needle)) { matchedOn.push(`column:${col.name}`); }
            else if (typeof col?.description === "string" && col.description.toLowerCase().includes(needle)) { matchedOn.push(`column:${col.name}`); }
          }
          for (const [encol, vals] of Object.entries(o?.enums ?? {})) {
            const valStr = JSON.stringify(vals).toLowerCase();
            if (encol.toLowerCase().includes(needle) || valStr.includes(needle)) matchedOn.push(`enum:${encol}`);
          }
          if (matchedOn.length) {
            hits.push({ database: db, schema, objectType, object: o.name, matchedOn: [...new Set(matchedOn)] });
            if (hits.length >= limit) return hits;
          }
        }
      }
    }
  }
  return hits;
}
