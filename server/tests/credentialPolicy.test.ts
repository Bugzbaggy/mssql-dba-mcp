import { test } from "node:test";
import assert from "node:assert/strict";
import { isPlaintextPasswordLiteral, PLAINTEXT_PASSWORD_ERROR } from "../src/credentialPolicy.js";

// The security contract: a real password baked into the config on disk is refused; only an
// empty value or a ${SQL_PASSWORD} placeholder is accepted there (the secret then comes from the
// OS credential store or the SQL_PASSWORD env var). See connectionManager.resolvePassword.

test("accepted on disk: empty / undefined / placeholder (secret supplied elsewhere)", () => {
  assert.equal(isPlaintextPasswordLiteral(undefined), false);
  assert.equal(isPlaintextPasswordLiteral(""), false);
  assert.equal(isPlaintextPasswordLiteral("${SQL_PASSWORD}"), false);
  assert.equal(isPlaintextPasswordLiteral("$SQL_PASSWORD"), false);
});

test("refused on disk: a real literal password in any form", () => {
  assert.equal(isPlaintextPasswordLiteral("hunter2"), true);
  assert.equal(isPlaintextPasswordLiteral("P@ss w0rd!"), true);
  assert.equal(isPlaintextPasswordLiteral("${SQL_PASSWORD}x"), true); // near-miss, not the exact placeholder
  assert.equal(isPlaintextPasswordLiteral(" "), true);                // whitespace is still a literal
});

test("the rejection message names the safe alternatives", () => {
  assert.match(PLAINTEXT_PASSWORD_ERROR, /SQL_CRED_TARGET/);
  assert.match(PLAINTEXT_PASSWORD_ERROR, /SQL_PASSWORD/);
  assert.match(PLAINTEXT_PASSWORD_ERROR, /must not live on disk/);
});
