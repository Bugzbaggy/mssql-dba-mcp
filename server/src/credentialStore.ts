/**
 * OS-native credential store reader (local / stdio installs only).
 *
 * Lets a local install pull its SQL login + password from the operating system's
 * secret store instead of a plaintext SQL_PASSWORD in ~/.claude.json:
 *   Windows  -> Credential Manager  (Generic credential; TargetName = <target>)
 *   macOS    -> Keychain            (generic-password; service = <target>)
 *   Linux    -> Secret Service      (libsecret; attribute service=<target>)
 *
 * One named entry holds BOTH the username and the password, so ~/.claude.json only
 * needs SQL_CRED_TARGET=<name> — no secret on disk. Enabled by connectionManager
 * when SQL_CRED_TARGET is set; falls back to SQL_USER/SQL_PASSWORD env if the entry
 * is missing. The HTTP transport (X-DB-* headers) never uses this path.
 *
 * Reads are synchronous (resolved once at startup) and shell out to the OS's own
 * tool — no third-party/native npm dependency. The password is returned in-process
 * and never logged.
 *
 * Create the entry:
 *   Windows : cmdkey /generic:SqlServerFleet /user:<login> /pass:<password>
 *   macOS   : security add-generic-password -U -s SqlServerFleet -a <login> -w <password>
 *   Linux   : secret-tool store --label=SqlServerFleet service SqlServerFleet account <login>
 */
import { execFileSync } from "node:child_process";

export interface OsCredential {
  user: string;
  password: string;
}

function log(message: string): void {
  // stdio transport: everything diagnostic goes to stderr (stdout is MCP framing).
  console.error(message);
}

/** Read <target> from the OS credential store. Returns undefined if absent/unsupported. */
export function readOsCredential(target: string): OsCredential | undefined {
  try {
    switch (process.platform) {
      case "win32":  return readWindows(target);
      case "darwin": return readMac(target);
      default:       return readLinux(target);
    }
  } catch (e) {
    log(`[db][cred] Could not read OS credential "${target}": ${(e as Error).message}`);
    return undefined;
  }
}

// ── Windows Credential Manager (advapi32 CredReadW via PowerShell P/Invoke) ──
// cmdkey /generic stores a CRED_TYPE_GENERIC credential but cannot read the secret
// back; CredReadW retrieves TargetName + UserName + CredentialBlob (the password).
// The target name is passed via env (CRED_TARGET), never interpolated into the script.
function readWindows(target: string): OsCredential | undefined {
  const script = `
$ErrorActionPreference='Stop'
$sig=@'
using System;
using System.Runtime.InteropServices;
public static class CredNative {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool CredReadW(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr cred);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
}
'@
Add-Type $sig | Out-Null
$p=[IntPtr]::Zero
if(-not [CredNative]::CredReadW($env:CRED_TARGET,1,0,[ref]$p)){ exit 2 }   # 1 = CRED_TYPE_GENERIC
$c=[System.Runtime.InteropServices.Marshal]::PtrToStructure($p,[type][CredNative+CREDENTIAL])
$pw=''
if($c.CredentialBlobSize -gt 0){ $pw=[System.Runtime.InteropServices.Marshal]::PtrToStringUni($c.CredentialBlob,$c.CredentialBlobSize/2) }
[CredNative]::CredFree($p)
[Console]::Out.Write((@{ user=$c.UserName; password=$pw } | ConvertTo-Json -Compress))
`;
  // 15 s was not enough and the failure was INVISIBLE. Measured on a slow workstation, this
  // exact script (Add-Type compiles C# on the fly, then CredRead) takes 16,011 ms — powershell.exe
  // alone costs 10-13 s to start there. It missed the old 15 s budget by about a second, threw,
  // and the catch below returned `undefined`, which every caller reads as "no such credential".
  // The symptom was "DB credentials not configured" on a box where the credential was present and
  // CredRead returned FOUND. 60 s by default, overridable for a slower or faster host.
  const timeoutMs = Math.max(5_000, parseInt(process.env.SQL_CRED_TIMEOUT_MS ?? "60000", 10) || 60_000);
  let out: string;
  try {
    out = execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      { env: { ...process.env, CRED_TARGET: target }, encoding: "utf8", windowsHide: true, timeout: timeoutMs },
    );
  } catch (e: unknown) {
    // "Not found" and "could not look" are DIFFERENT ANSWERS — the rule this codebase applies to
    // sys.dm_server_memory_dumps and get_host_dll_versions applies to its own credential store
    // too. The helper exits 2 when the target genuinely does not exist; anything else (a timeout,
    // a blocked ExecutionPolicy, powershell.exe missing) is a failure to MEASURE and must say so,
    // or a healthy credential looks identical to an absent one.
    const err = e as { status?: number; signal?: string; killed?: boolean; message?: string };
    const notFound = err?.status === 2 && !err?.killed;
    if (!notFound) {
      const why = err?.killed || err?.signal === "SIGTERM"
        ? `the read did not finish within ${timeoutMs} ms (raise SQL_CRED_TIMEOUT_MS)`
        : (err?.message ?? "unknown error");
      log(
        `[cred] Could NOT READ the OS credential store for "${target}" — this is NOT the same as ` +
        `the entry being absent: ${why}. Connections that rely on it will fail as "credentials ` +
        `not configured" until this is resolved.`,
      );
    }
    return undefined;
  }
  const parsed = JSON.parse(out) as { user?: string; password?: string };
  if (!parsed.password) return undefined;
  return { user: parsed.user ?? "", password: parsed.password };
}

// ── macOS Keychain (security find-generic-password) ──
function readMac(target: string): OsCredential | undefined {
  let password: string;
  try {
    password = execFileSync("security", ["find-generic-password", "-s", target, "-w"], { encoding: "utf8" })
      .replace(/\r?\n$/, "");
  } catch {
    return undefined; // item not found
  }
  if (!password) return undefined;
  let user = "";
  try {
    const attrs = execFileSync("security", ["find-generic-password", "-s", target], { encoding: "utf8" });
    user = attrs.match(/"acct"<blob>="([^"]*)"/)?.[1] ?? "";
  } catch { /* leave user blank; password still usable */ }
  return { user, password };
}

// ── Linux Secret Service (libsecret / secret-tool) ──
function readLinux(target: string): OsCredential | undefined {
  let password: string;
  try {
    password = execFileSync("secret-tool", ["lookup", "service", target], { encoding: "utf8" }).replace(/\r?\n$/, "");
  } catch {
    return undefined;
  }
  if (!password) return undefined;
  let user = "";
  try {
    user = execFileSync("secret-tool", ["lookup", "service", target, "attr", "account"], { encoding: "utf8" })
      .replace(/\r?\n$/, "");
  } catch { /* optional account attribute not present */ }
  return { user, password };
}
