/**
 * Local-install credential policy.
 *
 * The SQL password must never live in a config file on disk. A literal (non-empty,
 * non-placeholder) password in INSTANCES / INSTANCES_FILE / fleet.json is refused at
 * startup — the secret must come from the OS credential store (SQL_CRED_TARGET) or the
 * SQL_PASSWORD env var. Enforced by connectionManager.resolvePassword.
 *
 * Kept in its own dependency-free module so the policy can be unit-tested without loading
 * the whole connection stack (mssql/tedious, TLS bundle, fleet resolution).
 */

/** The accepted config placeholders that mean "fill this from the env / OS store, not from disk". */
const PASSWORD_PLACEHOLDERS = new Set(["${SQL_PASSWORD}", "$SQL_PASSWORD"]);

/**
 * True when `raw` is a real password baked into the config on disk — i.e. a non-empty value
 * that is NOT one of the accepted placeholders. That is the case we refuse.
 */
export function isPlaintextPasswordLiteral(raw?: string): boolean {
  return !!raw && !PASSWORD_PLACEHOLDERS.has(raw);
}

export const PLAINTEXT_PASSWORD_ERROR =
  "Refusing to start: a plaintext SQL password was found in the instance config " +
  "(INSTANCES / INSTANCES_FILE). The password must not live on disk. Remove it — leave " +
  '"password" empty or set it to "${SQL_PASSWORD}" — and supply the secret via SQL_CRED_TARGET ' +
  "(OS credential store: Windows Credential Manager / macOS Keychain / libsecret — preferred) " +
  "or the SQL_PASSWORD environment variable.";
