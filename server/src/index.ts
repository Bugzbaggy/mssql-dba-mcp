import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { registerTools } from "./tools.js";
import { initInstances, DEFAULT_INSTANCE, credentialContext } from "./connectionManager.js";
import { runReportCli } from "./reportCli.js";
import {
  loadAuthConfig,
  buildVerifier,
  buildProtectedResourceMetadata,
  identityFromAuth,
} from "./auth.js";
import type { Request, RequestHandler } from "express";

// ─────────────────────────────────────────────────────────────────────────────
// Logging — in stdio mode stdout is the MCP JSON-RPC channel, so all human-facing
// logging MUST go to stderr or it corrupts the protocol stream.
// ─────────────────────────────────────────────────────────────────────────────
const log = (msg: string) => console.error(msg);

const TRANSPORT = (process.env.MCP_TRANSPORT ?? "stdio").toLowerCase();

initInstances();

const SERVER_NAME = process.env.SERVER_NAME ?? "sql-server-dba";

function createServer(): McpServer {
  const s = new McpServer({ name: SERVER_NAME, version: "1.0.0" });
  registerTools(s);
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// stdio transport (default) — the MCP client (Claude Code / VS Code Copilot /
// Claude Desktop) spawns this process and talks over stdin/stdout. No network
// port is opened and the SQL credentials stay scoped to this child process.
// ─────────────────────────────────────────────────────────────────────────────
async function startStdio(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log(`${SERVER_NAME} MCP server ready (stdio); toolset=${process.env.TOOLSET ?? "dba"}; default instance: ${DEFAULT_INSTANCE} (read-only)`);
}

// Each user sends their OWN SQL login as request headers (X-DB-User / X-DB-Password).
// The credentials are used only for the lifetime of the request (placed in the
// credentialContext that connectionManager.getPool reads) and are never persisted.
function credsFromHeaders(req: Request): { user: string; password: string } {
  const header = (name: string): string => {
    const v = req.headers[name];
    return (Array.isArray(v) ? v[0] : v) ?? "";
  };
  return { user: header("x-db-user"), password: header("x-db-password") };
}

// Build the per-request credential context. The SQL login/password still come from
// headers (the per-user-identity contract — ADR-001), but when Entra auth is enabled
// we also attach the verified identity + token: it audits WHO the human is, and is the
// OBO user-assertion for the per-instance SQL token exchange (Path A) when enabled.
function contextFromRequest(req: Request) {
  return { ...credsFromHeaders(req), entra: identityFromAuth(req.auth) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Streamable HTTP transport (opt-in: MCP_TRANSPORT=http) — for the shared,
// long-lived service on the MCP platform. One McpServer instance per session;
// every request runs as the caller's own SQL login (per-user identity preserved).
// ─────────────────────────────────────────────────────────────────────────────
async function startHttp(): Promise<void> {
  const { default: express } = await import("express");
  const PORT = parseInt(process.env.PORT ?? "3000", 10);
  const app = express();
  app.set("trust proxy", process.env.MCP_TRUST_PROXY === "1");

  // Security headers (hand-rolled — JSON-only endpoint, so no helmet dependency needed).
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    next();
  });

  // ── Microsoft Entra OAuth (Resource Server) ───────────────────────────────
  // OFF by default (MCP_AUTH_MODE=off) so the header-credential deployment keeps
  // working. When "required", every /mcp request must carry a valid Entra JWT for
  // our API audience; the verified identity is threaded into the request context.
  const authCfg = loadAuthConfig();
  const mcpAuthGuard: RequestHandler[] = [];
  if (authCfg.mode !== "off") {
    const resourceMetadataUrl = `${authCfg.resourceUrl.replace(/\/mcp$/, "")}/.well-known/oauth-protected-resource`;
    // Publish Protected Resource Metadata (RFC 9728) so a client that gets a 401 can
    // discover which authorization server (Entra, our tenant) to authenticate against.
    app.get("/.well-known/oauth-protected-resource", (_req, res) => {
      res.json(buildProtectedResourceMetadata(authCfg));
    });
    if (authCfg.mode === "required") {
      mcpAuthGuard.push(
        requireBearerAuth({
          verifier: buildVerifier(authCfg),
          requiredScopes: authCfg.requiredScopes,
          resourceMetadataUrl,
        }),
      );
    }
    log(`[auth] Entra OAuth mode=${authCfg.mode}; audience=${authCfg.audience}; issuer=${authCfg.issuer}`);
  } else {
    log(`[auth] Entra OAuth disabled (MCP_AUTH_MODE=off) — using X-DB-* header credentials only`);
  }

  // Lightweight fixed-window rate limit on /mcp, keyed by SOURCE IP ONLY. It used to
  // include the X-DB-User header, but that header is attacker-controlled: rotating it
  // let one IP mint unlimited buckets and so sail past the cap while credential-stuffing
  // many SQL logins. Keying on req.ip alone bounds per-source request volume regardless
  // of which login is attempted. Tune with MCP_RATE_LIMIT_PER_MIN (0 disables); in-memory,
  // expired keys pruned every minute. (req.ip honours X-Forwarded-For only when
  // MCP_TRUST_PROXY=1, i.e. behind a trusted reverse proxy.)
  const RL_MAX = parseInt(process.env.MCP_RATE_LIMIT_PER_MIN ?? "120", 10);
  const rlHits = new Map<string, { count: number; resetAt: number }>();
  if (RL_MAX > 0) {
    setInterval(() => { const t = Date.now(); for (const [k, v] of rlHits) if (t > v.resetAt) rlHits.delete(k); }, 60_000).unref();
  }
  app.use("/mcp", (req, res, next) => {
    if (RL_MAX <= 0) return next();
    const key = req.ip ?? "unknown";
    const now = Date.now();
    let e = rlHits.get(key);
    if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + 60_000 }; rlHits.set(key, e); }
    e.count++;
    if (e.count > RL_MAX) {
      res.setHeader("Retry-After", Math.ceil((e.resetAt - now) / 1000).toString());
      res.status(429).json({ error: "Too many requests" });
      return;
    }
    next();
  });

  app.use(express.json());

  // DNS-rebinding / Origin protection for the Streamable-HTTP transport. A browser page
  // can't be stopped from POSTing to a known URL, so without Host/Origin validation a
  // malicious site could drive a reachable MCP instance via DNS rebinding. Enabled only
  // when an allowlist is configured (so an unconfigured deployment isn't broken by
  // rejecting its own legitimate Host) — set MCP_ALLOWED_HOSTS (and optionally
  // MCP_ALLOWED_ORIGINS) to the public host(s), comma-separated, to turn it on.
  const allowedHosts   = (process.env.MCP_ALLOWED_HOSTS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const allowedOrigins = (process.env.MCP_ALLOWED_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const dnsRebindingProtection = allowedHosts.length > 0 || allowedOrigins.length > 0;
  if (dnsRebindingProtection) {
    log(`[mcp] DNS-rebinding protection ON (allowedHosts=${allowedHosts.join(",") || "-"}; allowedOrigins=${allowedOrigins.join(",") || "-"})`);
  } else {
    log(`[mcp] DNS-rebinding protection OFF — set MCP_ALLOWED_HOSTS (and optionally MCP_ALLOWED_ORIGINS) to enable Host/Origin validation`);
  }

  const transports = new Map<string, StreamableHTTPServerTransport>();

  app.post("/mcp", ...mcpAuthGuard, async (req, res) => {
    // Run the whole request — including the tool callbacks the transport invokes —
    // inside this caller's credential context, so getPool connects as their login.
    await credentialContext.run(contextFromRequest(req), async () => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && transports.has(sessionId)) {
        await transports.get(sessionId)!.handleRequest(req, res, req.body);
        return;
      }

      if (!sessionId && isInitializeRequest(req.body)) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableDnsRebindingProtection: dnsRebindingProtection,
          ...(allowedHosts.length ? { allowedHosts } : {}),
          ...(allowedOrigins.length ? { allowedOrigins } : {}),
          onsessioninitialized: (newId) => {
            transports.set(newId, transport);
            log(`[mcp] New session: ${newId}`);
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            transports.delete(transport.sessionId);
            log(`[mcp] Session closed: ${transport.sessionId}`);
          }
        };

        const sessionServer = createServer();
        await sessionServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }

      res.status(400).json({ error: "Bad request" });
    });
  });

  app.get("/mcp", ...mcpAuthGuard, async (req, res) => {
    await credentialContext.run(contextFromRequest(req), async () => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      const transport = sessionId ? transports.get(sessionId) : undefined;
      if (!transport) {
        res.status(400).json({ error: "Session not found", sessionId });
        return;
      }
      await transport.handleRequest(req, res);
    });
  });

  app.delete("/mcp", ...mcpAuthGuard, async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (sessionId) {
      const transport = transports.get(sessionId);
      if (transport) {
        await transport.close();
        transports.delete(sessionId);
      }
    }
    res.status(200).end();
  });

  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      server: "sql-server-dba-mcp",
      version: "1.0.0",
      default_instance: DEFAULT_INSTANCE,
      sessions: transports.size,
      timestamp: new Date().toISOString(),
    });
  });

  // Bind to loopback by default; the platform deployment behind a TLS-terminating proxy
  // sets MCP_BIND_HOST=0.0.0.0 to expose it. This prevents a dev laptop / un-proxied node
  // from silently exposing the credential-accepting endpoint to the local network.
  const BIND_HOST = process.env.MCP_BIND_HOST ?? "127.0.0.1";
  app.listen(PORT, BIND_HOST, () => {
    log(`sql-server-dba MCP server started (http) on ${BIND_HOST}:${PORT}`);
    log(`  MCP endpoint:  /mcp   Health: /health`);
    log(`  Default instance: ${DEFAULT_INSTANCE} (read-only); rate limit: ${RL_MAX || "off"} req/min/user`);
    if (BIND_HOST === "0.0.0.0") log(`  [warn] bound to 0.0.0.0 — ensure TLS terminates upstream and access is restricted`);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Headless report mode (`node dist/index.js report --region sg --recipients <email>`).
// Runs the SAME dbatools health check + renders the SAME HTML as the run_health_check
// MCP tool (shared runHealthReport/generateHtmlReport) and emails it via the fleet's
// Database Mail (sendDbMail). This is the engine behind the scheduled weekly Slack report
// — one report definition, two entrypoints (interactive tool + this CLI). Needs
// SQL_USER/SQL_PASSWORD (+ INSTANCES_FILE) in the environment, dbatools + PowerShell on
// this host, and a Database-Mail-capable login.
// ─────────────────────────────────────────────────────────────────────────────
if (process.argv[2] === "report") {
  runReportCli(process.argv.slice(3)).then(() => process.exit(0)).catch((err) => {
    log(`[report][fatal] ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    process.exit(1);
  });
} else {
  const start = TRANSPORT === "http" ? startHttp : startStdio;
  start().catch((err) => {
    log(`[fatal] ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    process.exit(1);
  });
}
