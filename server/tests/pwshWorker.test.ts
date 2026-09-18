import { test } from "node:test";
import assert from "node:assert/strict";
import { PwshWorker } from "../src/pwshWorker.ts";
import { callDbatools } from "../src/dbatools.ts";

test("round-trips a request and correlates the response by id", async () => {
  const w = new PwshWorker({ importDbatools: false });
  await w.start();
  try {
    const rows = await w.call("Write-Output", { InputObject: "hello" });
    assert.ok(Array.isArray(rows));
    assert.equal(rows.length, 1);
    assert.equal(rows[0], "hello");
  } finally {
    await w.stop();
  }
});

test("concurrent calls do not cross their responses", async () => {
  const w = new PwshWorker({ importDbatools: false });
  await w.start();
  try {
    const results = await Promise.all(
      [1, 2, 3, 4, 5].map((n) => w.call("Write-Output", { InputObject: `v${n}` })),
    );
    assert.deepEqual(results.map((r) => (r as string[])[0]), ["v1", "v2", "v3", "v4", "v5"]);
  } finally {
    await w.stop();
  }
});

test("a timed-out call rejects and does not wedge the worker", async () => {
  const w = new PwshWorker({ importDbatools: false, timeoutSec: 1 });
  await w.start();
  try {
    await assert.rejects(
      () => w.call("Start-Sleep", { Seconds: 10 }, 1),
      /timed out after 1s/,
    );
    // The worker must still answer afterwards - which means restarting the process
    // it just killed. A cold pwsh boot measured 1.2-1.9s on this machine, well past
    // the worker's own 1s default timeoutSec, so give this call its own realistic
    // budget rather than inheriting the deliberately-tight one used to trigger the
    // timeout above; it is restart latency being budgeted here, not the assertion
    // being weakened.
    const rows = await w.call("Write-Output", { InputObject: "alive" }, 15);
    assert.equal((rows as string[])[0], "alive");
  } finally {
    await w.stop();
  }
});

test("in-flight calls reject when the worker exits", async () => {
  const w = new PwshWorker({ importDbatools: false, timeoutSec: 30 });
  await w.start();
  try {
    const inflight = w.call("Start-Sleep", { Seconds: 30 });
    setTimeout(() => { void w.stop(); }, 200);
    await assert.rejects(() => inflight, /exited|not running/);
  } finally {
    await w.stop();
  }
});

test("refuses work beyond the queue cap instead of buffering without bound", async () => {
  const w = new PwshWorker({ importDbatools: false, maxQueue: 2, timeoutSec: 30 });
  await w.start();
  try {
    const a = w.call("Start-Sleep", { Seconds: 5 });
    const b = w.call("Start-Sleep", { Seconds: 5 });
    await assert.rejects(() => w.call("Write-Output", { InputObject: "x" }), /queue full/);
    void a.catch(() => {}); void b.catch(() => {});
  } finally {
    await w.stop();
  }
});

test("a write cmdlet is refused before it can reach the worker", async () => {
  await assert.rejects(
    () => callDbatools("Remove-DbaDatabase", { Database: "anything" }),
    /read-only|not allowed|refus/i,
  );
});

test("a large stderr write does not wedge the worker", async () => {
  const w = new PwshWorker({ importDbatools: false, timeoutSec: 20 });
  await w.start();
  try {
    // Write >= 256KB directly to the child's real OS-level stderr (bypassing PowerShell's
    // own warning/error streams so this reproduces the OS pipe filling up regardless of
    // how dbatools happens to write its own warnings). On an unpatched worker (stderr
    // piped, never read anywhere) this blocks the process once the OS pipe buffer fills -
    // and because the process is now blocked mid-write, it never gets back around to
    // reading the next request off stdin either. Confirmed empirically before this fix
    // existed: an equivalent standalone spawn (stderr piped, undrained) never returned,
    // even after 120s, for a 2MB stderr write.
    const rows1 = await w.call("Invoke-Expression", { Command: "[Console]::Error.Write([string]::new('x', 300000)); 'wrote-stderr'" }, 20);
    assert.equal((rows1 as string[])[0], "wrote-stderr");

    // The real assertion: a call sent AFTER that big stderr write must still get an
    // answer. Before the fix this times out because the worker is wedged.
    const rows2 = await w.call("Write-Output", { InputObject: "still-alive" }, 20);
    assert.equal((rows2 as string[])[0], "still-alive");
  } finally {
    await w.stop();
  }
});

test("restarts resets to 0 after a successful call following a restart", async () => {
  const w = new PwshWorker({ importDbatools: false, timeoutSec: 1, maxRestarts: 5 });
  await w.start();
  try {
    // Force one unexpected-exit restart, the same way the existing timeout test does.
    await assert.rejects(() => w.call("Start-Sleep", { Seconds: 10 }, 1), /timed out after 1s/);
    assert.equal(w.restarts, 1);

    // A call that actually completes proves the worker is healthy again - restarts must
    // go back to 0, or the field stops meaning "consecutive" as its own doc comment
    // promises, and a long-lived server would eventually be bricked by restarts that
    // are nowhere near each other in time.
    const rows = await w.call("Write-Output", { InputObject: "alive" }, 15);
    assert.equal((rows as string[])[0], "alive");
    assert.equal(w.restarts, 0);
  } finally {
    await w.stop();
  }
});

test("a worker that fails to spawn rejects calls instead of crashing the process", async () => {
  const prevPwshExe = process.env.PWSH_EXE;
  // Deliberately not a real binary anywhere on PATH: forces the ChildProcess's own
  // 'error' event (ENOENT), distinct from an exit or a broken-pipe write failure.
  process.env.PWSH_EXE = "definitely-not-a-real-pwsh-binary-12345";
  try {
    const w = new PwshWorker({ importDbatools: false, timeoutSec: 5 });
    try {
      await assert.rejects(
        () => w.call("Write-Output", { InputObject: "x" }),
        /Failed to launch/,
      );
    } finally {
      await w.stop();
    }
  } finally {
    if (prevPwshExe === undefined) delete process.env.PWSH_EXE;
    else process.env.PWSH_EXE = prevPwshExe;
  }
});
