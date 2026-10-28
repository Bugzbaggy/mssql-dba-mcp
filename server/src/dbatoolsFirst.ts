// Wave 3 is the live-diagnostics set - the tools reached for during an incident. Both
// implementations are kept so the cost can be compared on real traffic instead of
// argued about: the DMV path stays the DEFAULT, and DBATOOLS_FIRST=1 opts in.
//
// Exactly "1", not any truthy string: an operator who sets DBATOOLS_FIRST=false meant
// to turn it OFF, and a loose check would do the opposite of what they asked.
//
// Never on the HTTP transport. The worker builds ONE credential at boot from the process
// environment, so on a shared HTTP service every caller would run as the server's own login -
// the per-user identity break that keeps the PowerShell-backed tools off HTTP entirely
// (registerDbatoolsTools). The DMV path uses the caller's own per-request credential.
export function dbatoolsFirst(): boolean {
  if ((process.env.MCP_TRANSPORT ?? "stdio").toLowerCase() === "http") return false;
  return process.env.DBATOOLS_FIRST === "1";
}

/**
 * Run whichever path is selected, falling back to DMV if the dbatools path fails.
 *
 * The fallback is deliberate: an opt-in performance experiment must never be the reason
 * a diagnostic tool is unavailable mid-incident. A worker crash degrades to the proven
 * path rather than to an error.
 */
export async function withFallback<T>(
  dbatoolsPath: () => Promise<T>,
  dmvPath: () => Promise<T>,
): Promise<T> {
  if (!dbatoolsFirst()) return dmvPath();
  try {
    return await dbatoolsPath();
  } catch (e) {
    console.error(`[dbatools-first] falling back to the DMV path: ${(e as Error).message}`);
    return dmvPath();
  }
}
