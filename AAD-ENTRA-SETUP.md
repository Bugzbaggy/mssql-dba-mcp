# Microsoft Entra OAuth for appdb-sql-mcp

How this MCP server authenticates with Microsoft Entra (Azure AD), how it relates
to the `the reference MCP server` server it was modelled on, and the step-by-step to enable the
two phases. Auth is **off by default** — nothing here changes the running
header-credential deployment until you set `MCP_AUTH_MODE`.

---

## 1. How `the reference MCP server` authenticates today (the model)

`the reference MCP server` is a Python FastMCP 3.x server using `AzureProvider` — an **OAuth
proxy**:

1. The user signs in to *that app's* Entra registration and receives a token for
   its custom API scope `api://{client_id}/access_as_user`.
2. FastMCP issues its **own** MCP JWT to the client (Claude), signed with
   `MCP_JWT_SECRET`, and stores + transparently refreshes the upstream Entra token.
3. In each tool it runs **On-Behalf-Of** (`EntraOBOToken`) to exchange the user's
   token for a **Power BI** access token, then calls the Power BI REST API as that
   user — so per-user permissions and row-level security apply. No shared service
   account.

The reason OBO drops straight in there: the Power BI REST API is a **bearer-token
HTTP API**. SQL Server is not — which is why appdb-sql-mcp's port is shaped
differently (below).

## 2. What appdb-sql-mcp does instead (Resource Server)

There is no `AzureProvider` equivalent in the TypeScript MCP SDK, and Entra has no
Dynamic Client Registration, so a 1:1 OAuth-proxy port would mean hand-writing a DCR
shim + token issuance. We don't. appdb-sql-mcp acts purely as an OAuth **Resource
Server**:

- It **verifies** Entra-issued access tokens (audience = our API) on every `/mcp`
  request, via Entra's JWKS — `server/src/auth.ts`.
- It publishes Protected Resource Metadata at
  `/.well-known/oauth-protected-resource` so a client that gets a `401` can discover
  which authorization server (Entra, our tenant) to use.
- The client (Claude) obtains tokens from Entra directly. Because Entra has no DCR,
  the client must use a **pre-registered** `client_id` (§5).

### Two phases

| | Phase B — JWT gate (deployable now) | Phase A — OBO into SQL (needs fleet work) |
|---|---|---|
| What the JWT proves | The human's identity, to gate `/mcp` | The human's identity, **passed into SQL** |
| SQL connection auth | Your `X-DB-*` SQL login (unchanged) | Entra access token (OBO), no SQL password |
| SQL audit shows | Your SQL login | **You** (the Entra principal) |
| Prerequisite | Entra app registration (§5) | §5 **and** Entra auth on every SQL node (§4) |
| Switches | `MCP_AUTH_MODE=required` | `+ ENTRA_SQL_OBO_ENABLED=1` and `entraAuth:true` per fleet entry |

Phase A preserves ADR-001 (per-user identity) at the
*SQL* layer — the literal equivalent of the reference MCP server's per-user RLS.

## 3. Fleet readiness — checked 2026-06-18

A `fan_out_query` across every configured SQL node (prod in each region, plus dev and staging):

- All are **SQL Server 2022** (major v16, builds 16.0.40xx–16.0.42xx) — Enterprise
  in prod, Developer in dev/staging. Entra auth is supported on this version.
- **Every node has zero Entra principals** (`sys.server_principals` `type` `E`/`X` = 0).
  No Entra admin, no Entra logins. **Entra auth is not configured anywhere.**

Conclusion: **Phase A is not available today.** Ship Phase B now; do §4 per node
before flipping any instance to `entraAuth:true`.

Re-run the readiness check any time:

```sql
SELECT @@SERVERNAME AS server_name,
       CAST(SERVERPROPERTY('ProductVersion') AS varchar(32)) AS version,
       (SELECT COUNT(*) FROM sys.server_principals WHERE type IN ('E','X')) AS entra_principals;
```

## 4. Step-by-step: enable Entra auth on a SQL Server 2022 node (Phase A prerequisite)

**Can SQL Server even take an Entra token? Yes — SQL Server 2022 only, and only when
enabled by Azure Arc.** Unlike Azure SQL DB/MI (Entra-native), a standalone SQL Server
2022 instance must be onboarded to **Azure Arc** and have the **Azure extension for SQL
Server** configure a *Microsoft Entra admin + a validation certificate*. Once that's
done, the engine accepts an Entra access token at TDS login — which is exactly what the
driver's `azure-active-directory-access-token` auth (our Path A) sends. No Arc + cert =
the engine has nothing to validate the token against, and login fails.

> **This fleet is on GCP and AWS, not Azure.** Arc works on any machine anywhere, but
> the first hurdle is non-trivial cloud/network/security work, not SQL: an Azure
> subscription + resource group, the Connected Machine agent on every node, outbound
> HTTPS egress to Azure, an Azure Key Vault, and a certificate. **Pilot on `dev-db1` or
> `staging-node1` first** — never a prod AG primary. Budget this as a cross-team project, not a
> config change.

### 4.0 Prerequisites (once)
- An Azure subscription + resource group to hold the Arc resources.
- An **Azure Key Vault** (same region you pick for Arc) holding a **certificate** SQL
  Server uses to authenticate to Entra. The Azure extension can generate it for you.
- Outbound **HTTPS (443)** from each SQL host to: `login.microsoftonline.com`,
  `management.azure.com`, `*.his.arc.azure.com`, `*.guestconfiguration.azure.com`,
  `pas.windows.net`, `*.vault.azure.net`, `graph.microsoft.com`. This is a firewall ask
  on the GCP/AWS side.
- Azure roles to onboard Arc + configure the extension (e.g. *Azure Connected Machine
  Onboarding* + *Contributor* on the RG), and a Global/Privileged-Role admin to consent
  the Graph permissions in 4.3.

### 4.1 Onboard each VM to Azure Arc
Install the Connected Machine agent (`AzureConnectedMachineAgent.msi`) on the SQL host, then:
```powershell
azcmagent connect `
  --resource-group <rg> `
  --tenant-id 00000000-0000-0000-0000-000000000000 `
  --location <azure-region> `
  --subscription-id <sub-id>
```

### 4.2 Confirm the Azure extension for SQL Server — and DON'T double-pay licensing
Arc auto-discovers the SQL instance and installs the *Azure extension for SQL Server*;
it appears under **Azure Arc → SQL Server instances**. **Set the license type to use
your existing licenses** or the extension defaults can switch on pay-as-you-go billing —
this fleet is already **Enterprise Edition: Core-based Licensing** (confirmed by the
probe), so set `LicenseType = Paid` (use existing license), not `PAYG`:
```bash
az sql server-arc ... --license-type Paid   # or set it in the portal SQL config blade
```

### 4.3 Configure Microsoft Entra authentication on the instance
Azure portal → the Arc-enabled SQL Server instance → **Microsoft Entra ID** blade → set:
- **Microsoft Entra admin** — a *group* (e.g. `sg-appdb-dba`), not a person.
- **Key Vault + certificate** — pick the KV and cert from 4.0.
- The extension creates/uses an **Entra app** for the instance and uploads the cert to
  it. Grant that app (or the Arc machine's managed identity) **Microsoft Graph**
  read perms — `User.Read.All`, `GroupMember.Read.All`, `Application.Read.All` — and
  **admin-consent** them, so the engine can resolve Entra users/group membership at login.

After Save, the SQL error log shows Entra authentication initialised, and the admin group
appears as an external principal:
```sql
SELECT name, type_desc FROM sys.server_principals WHERE type IN ('E','X');  -- 'E' user, 'X' group
```

### 4.4 Create the login the MCP connects as + read-only grants
Mirror the existing monitoring login's least-privilege rights (don't grant more):
```sql
CREATE LOGIN [sg-appdb-dba] FROM EXTERNAL PROVIDER;   -- an Entra group
GRANT VIEW SERVER STATE, VIEW ANY DEFINITION TO [sg-appdb-dba];
-- per database the profile reads:
--   CREATE USER [sg-appdb-dba] FROM EXTERNAL PROVIDER;
--   ALTER ROLE db_datareader ADD MEMBER [sg-appdb-dba];
```

### 4.5 Availability Group nodes — do every replica
Entra auth config (4.1–4.3) and **server-level** logins (4.4 `CREATE LOGIN`) are
per-instance and **do not replicate** — run them on **every replica** (e.g. `region3-node1`
*and* `region3-node2`) with the **same** Entra admin group and the same external login name, or
a post-failover connection breaks. *Database* users (`CREATE USER`) live in the DB and
travel with the AG. Skip the witnesses (no SQL engine). Mind the fleet quirks while you're
on the box (Lock Pages in Memory, the EDR agent injection) — see
`runbooks/known-fleet-quirks.md`.

### 4.6 Verify token sign-in before wiring the MCP
From a host with the Entra identity, prove the engine accepts a token:
```
sqlcmd -S <host>,1433 -G -d AppCatalog -Q "SELECT SUSER_SNAME();"
```
`-G` = interactive Entra auth. If that returns your UPN, the OBO path will work too.

### 4.7 Flip the instance on in the MCP
Set `entraAuth: true` on that node's entry in `fleet.json`, set `ENTRA_SQL_OBO_ENABLED=1`
and `ENTRA_CLIENT_SECRET`, restart. Leave `entraAuth` off for any node that hasn't passed
4.6 — the server falls back to SQL-login auth for unflagged nodes, so a partial rollout is
safe and reversible.

Microsoft reference: **"Configure Microsoft Entra authentication for SQL Server"**
(SQL Server enabled by Azure Arc).

## 5. Entra app registration for the MCP server (both phases)

One confidential-client app registration, mirroring the reference MCP server's:

1. **Expose an API** → App ID URI `api://{client_id}` → add scope `access_as_user`
   (admins + users). → `ENTRA_API_AUDIENCE`, `ENTRA_REQUIRED_SCOPES`.
2. **Access token version 2** → Manifest `"requestedAccessTokenVersion": 2`.
3. **Client secret** (Phase A OBO only) → `ENTRA_CLIENT_SECRET`.
4. **Delegated permission** for the SQL resource (Phase A): *Azure SQL Database* →
   `user_impersonation`, admin-consented — so OBO can mint the
   `https://database.windows.net/.default` token.
5. **Public client for Claude**: because Entra has no DCR, register (or reuse) a
   public client app and add it as a known/authorized client so the MCP client can
   run the auth-code + PKCE flow against `api://{client_id}/access_as_user`.

## 6. Platform / config

| Key | Phase | Value |
|---|---|---|
| `MCP_AUTH_MODE` | B | `required` |
| `ENTRA_CLIENT_ID` | B | app (client) ID |
| `ENTRA_API_AUDIENCE` | B | `api://{client_id}` |
| `ENTRA_REQUIRED_SCOPES` | B | `access_as_user` |
| `MCP_PUBLIC_URL` | B | deployed URL (derives the resource id) |
| `ENTRA_SQL_OBO_ENABLED` | A | `1` |
| `ENTRA_CLIENT_SECRET` | A | **secret** — confidential client |

Network egress required: `https://login.microsoftonline.com` (token + JWKS) and,
for Phase A, the SQL nodes already reachable.
