#!/usr/bin/env node
/**
 * NAT-06: Offline `FROM scratch` Podman OCI container integration test for `os-native`.
 *
 * Verifies:
 * 1. `cargo xtask container --build` builds a minimal `FROM scratch` OCI image completely offline (`--network=none`).
 * 2. `podman run --network=none -v <state>:/state` boots Stage 0 -> Stage 1 -> Stage 2 offline,
 *    persists CowFs root data across clean `SIGTERM` restart AND across `podman kill` (`SIGKILL`) crash recovery.
 * 3. `podman run -p 127.0.0.1:<port>:7420 -v <state>:/state` serves authenticated `HostAdapter v2`
 *    over TCP and WebSocket (`ws://`), supports host `os-native exec` and `os-native attach`,
 *    and live `token revoke` disconnects active sessions while keeping the container OS alive.
 */

import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const BUNDLE_DIR = process.env.OS_NATIVE_TEST_BUNDLE || "/tmp/os-native-test-bundle";
const OS_NATIVE_BIN = process.env.OS_NATIVE_BIN;
const XTASK_BIN = process.env.XTASK_BIN;

if (!OS_NATIVE_BIN || !fs.existsSync(OS_NATIVE_BIN)) {
  console.error("NAT-06 requires OS_NATIVE_BIN pointing to the compiled release os-native binary");
  process.exit(1);
}
if (!XTASK_BIN || !fs.existsSync(XTASK_BIN)) {
  console.error("NAT-06 requires XTASK_BIN pointing to the compiled xtask binary");
  process.exit(1);
}
if (!fs.existsSync(path.join(BUNDLE_DIR, "release.json"))) {
  console.error(`NAT-06 requires signed Release v2 bundle at ${BUNDLE_DIR}`);
  process.exit(1);
}

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "os-native-nat06-"));
const podmanRoot = path.join(workDir, "podman-root");
const podmanRunroot = path.join(workDir, "podman-runroot");
const stageDir = path.join(workDir, "stage");
const stateDir = path.join(workDir, "state");
fs.mkdirSync(podmanRoot, { recursive: true });
fs.mkdirSync(podmanRunroot, { recursive: true });
fs.mkdirSync(stateDir, { recursive: true });

const IMAGE_TAG = "localhost/os-native:nat06";
const activeContainers = new Set();

function podman(args, opts = {}) {
  return execFileSync(
    "podman",
    ["--root", podmanRoot, "--runroot", podmanRunroot, ...args],
    { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], ...opts },
  );
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
  });
}

function podmanLogs(cid) {
  const res = spawnSync(
    "podman",
    ["--root", podmanRoot, "--runroot", podmanRunroot, "logs", cid],
    { encoding: "utf8" },
  );
  const state = spawnSync(
    "podman",
    [
      "--root",
      podmanRoot,
      "--runroot",
      podmanRunroot,
      "inspect",
      "-f",
      "exit={{.State.ExitCode}} err={{.State.Error}}",
      cid,
    ],
    { encoding: "utf8" },
  );
  return `${(state.stdout || "").trim()}\nSTDOUT:\n${res.stdout || ""}\nSTDERR:\n${res.stderr || ""}`;
}

async function waitForHealthy(cid, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = "";
  while (Date.now() < deadline) {
    try {
      const out = podman([
        "exec",
        cid,
        "/usr/local/bin/os-native",
        "inspect",
        "--state",
        "/state",
        "--json",
      ]);
      const info = JSON.parse(out);
      if (info.boot_healthy === true && info.stage === "stage2") {
        return info;
      }
      lastErr = `stage=${info.stage} boot_healthy=${info.boot_healthy}`;
    } catch (e) {
      lastErr = e.stderr ? String(e.stderr) : String(e.message);
      // Fail fast if container already exited.
      try {
        const running = podman(["inspect", "-f", "{{.State.Running}}", cid]).trim();
        if (running !== "true") {
          const logs = podmanLogs(cid);
          throw new Error(`Container ${cid} exited before ready.\n${logs}`);
        }
      } catch (inner) {
        if (String(inner.message).includes("exited before ready")) throw inner;
      }
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  const logs = podmanLogs(cid);
  throw new Error(`Timed out waiting for container ${cid} boot_healthy (${lastErr})\n${logs}`);
}

function cleanup() {
  for (const cid of activeContainers) {
    try {
      podman(["rm", "-f", cid]);
    } catch {
      // ignore
    }
  }
  try {
    podman(["rmi", "-f", IMAGE_TAG]);
  } catch {
    // ignore
  }
  try {
    execFileSync("podman", ["unshare", "rm", "-rf", workDir], { stdio: "ignore" });
  } catch {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

async function main() {
  console.log("[NAT-06] 1. Staging and building FROM scratch OCI image offline via xtask container...");
  execFileSync(
    XTASK_BIN,
    [
      "container",
      "--bundle",
      BUNDLE_DIR,
      "--out",
      stageDir,
      "--bin",
      OS_NATIVE_BIN,
      "--tag",
      IMAGE_TAG,
      "--build",
      "--podman-root",
      podmanRoot,
      "--podman-runroot",
      podmanRunroot,
    ],
    { stdio: "inherit" },
  );

  // Confirm minimal FROM scratch staging contains no host shell.
  assert.equal(fs.existsSync(path.join(stageDir, "rootfs/bin/sh")), false, "scratch rootfs must not contain host /bin/sh");
  assert.equal(fs.existsSync(path.join(stageDir, "rootfs/usr/local/bin/os-native")), true, "scratch rootfs must contain os-native");

  console.log("[NAT-06] 2. Booting container completely offline (--network=none) and writing CowFs state...");
  const cid1 = podman([
    "run",
    "-d",
    "--network=none",
    "-v",
    `${stateDir}:/state`,
    IMAGE_TAG,
    "--no-console-shell",
  ]).trim();
  activeContainers.add(cid1);

  const info1 = await waitForHealthy(cid1);
  assert.equal(info1.boot_healthy, true);
  assert.ok(info1.root_volume, "expected mounted root volume");

  const tok1 = JSON.parse(
    podman([
      "exec",
      cid1,
      "/usr/local/bin/os-native",
      "token",
      "create",
      "--state",
      "/state",
      "--uid",
      "0",
      "--label",
      "nat06-offline",
      "--json",
    ]),
  );
  assert.ok(tok1.token);

  const writeOut = podman([
    "exec",
    cid1,
    "/usr/local/bin/os-native",
    "exec",
    "--target",
    "unix:///state/seat.sock",
    "--token",
    tok1.token,
    "--",
    "/bin/sh",
    "-c",
    "mkdir -p /home/user && printf 'podman-offline-persist\\n' > /home/user/podman.txt && chown 1000:1000 /home/user/podman.txt && cat /home/user/podman.txt",
  ]);
  assert.equal(writeOut.trim(), "podman-offline-persist");

  console.log("[NAT-06] 3. Clean SIGTERM stop + offline restart + real podman kill (SIGKILL) recovery...");
  podman(["stop", "-t", "10", cid1]);
  podman(["rm", cid1]);
  activeContainers.delete(cid1);

  const cid2 = podman([
    "run",
    "-d",
    "--network=none",
    "-v",
    `${stateDir}:/state`,
    IMAGE_TAG,
    "--no-console-shell",
  ]).trim();
  activeContainers.add(cid2);

  const info2 = await waitForHealthy(cid2);
  assert.equal(info2.root_volume, info1.root_volume, "restart must reuse persistent CowFs volume");

  const writeCrash = podman([
    "exec",
    cid2,
    "/usr/local/bin/os-native",
    "exec",
    "--target",
    "unix:///state/seat.sock",
    "--token",
    tok1.token,
    "--",
    "/bin/sh",
    "-c",
    "cat /home/user/podman.txt && printf 'podman-survived-sigkill\\n' > /home/user/sigkill.txt",
  ]);
  assert.equal(writeCrash.trim(), "podman-offline-persist");
  // Wait for Contract §2.15 5s dirty-commit deadline to advance root_epoch durably before SIGKILL.
  const commitDeadline = Date.now() + 10_000;
  while (true) {
    const cur = JSON.parse(
      podman(["exec", cid2, "/usr/local/bin/os-native", "inspect", "--state", "/state", "--json"]),
    );
    if (cur.root_epoch > info2.root_epoch) break;
    assert.ok(Date.now() < commitDeadline, "timed out waiting for CowFs dirty-commit before SIGKILL");
    await new Promise((r) => setTimeout(r, 250));
  }

  // Hard SIGKILL!
  podman(["kill", cid2]);
  podman(["rm", cid2]);
  activeContainers.delete(cid2);

  console.log("[NAT-06] 4. Booting with published port 7420 to verify SIGKILL recovery + remote HostAdapter v2...");
  const hostPort = await getFreePort();
  const cid3 = podman([
    "run",
    "-d",
    "-p",
    `127.0.0.1:${hostPort}:7420`,
    "-v",
    `${stateDir}:/state`,
    IMAGE_TAG,
  ]).trim();
  activeContainers.add(cid3);

  const info3 = await waitForHealthy(cid3);
  assert.equal(info3.root_volume, info1.root_volume, "post-SIGKILL recovery must keep root volume");

  const tokRemote = JSON.parse(
    podman([
      "exec",
      cid3,
      "/usr/local/bin/os-native",
      "token",
      "create",
      "--state",
      "/state",
      "--uid",
      "1000",
      "--label",
      "nat06-remote",
      "--json",
    ]),
  );

  // Remote exec over WebSocket (`ws://`) from the HOST into the container.
  const wsOut = execFileSync(
    OS_NATIVE_BIN,
    [
      "exec",
      "--target",
      `ws://127.0.0.1:${hostPort}/`,
      "--token",
      tokRemote.token,
      "--",
      "/bin/sh",
      "-c",
      "id -u && cat /home/user/podman.txt && cat /home/user/sigkill.txt",
    ],
    { encoding: "utf8" },
  );
  assert.equal(
    wsOut.trim().split("\n").join("|"),
    "1000|podman-offline-persist|podman-survived-sigkill",
  );

  // Remote exec over raw TCP JSON-lines (`tcp://`) from the HOST into the container.
  const tcpOut = execFileSync(
    OS_NATIVE_BIN,
    [
      "exec",
      "--target",
      `tcp://127.0.0.1:${hostPort}`,
      "--token",
      tokRemote.token,
      "--",
      "/bin/sh",
      "-c",
      "echo host-tcp-ok",
    ],
    { encoding: "utf8" },
  );
  assert.equal(tcpOut.trim(), "host-tcp-ok");

  // Remote interactive `attach` over `ws://`, then live `token revoke` disconnects client while container stays alive!
  console.log("[NAT-06] 5. Testing live remote attach + token revocation...");
  const attachProc = spawn(
    OS_NATIVE_BIN,
    [
      "attach",
      "--target",
      `ws://127.0.0.1:${hostPort}/`,
      "--token",
      tokRemote.token,
      "--seat",
      "0",
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );

  let attachStdout = "";
  let attachStderr = "";
  attachProc.stdout.on("data", (chunk) => {
    attachStdout += chunk.toString("utf8");
  });
  attachProc.stderr.on("data", (chunk) => {
    attachStderr += chunk.toString("utf8");
  });

  attachProc.stdin.write("echo NAT06_SEAT_ALIVE\n");
  const seatDeadline = Date.now() + 10000;
  while (!attachStdout.includes("NAT06_SEAT_ALIVE")) {
    if (attachProc.exitCode !== null) {
      throw new Error(`attach exited early (${attachProc.exitCode}): stdout=${attachStdout} stderr=${attachStderr}`);
    }
    assert.ok(Date.now() < seatDeadline, `timed out waiting for seat output: stdout=${attachStdout} stderr=${attachStderr}`);
    await new Promise((r) => setTimeout(r, 100));
  }

  const revokeReply = JSON.parse(
    podman([
      "exec",
      cid3,
      "/usr/local/bin/os-native",
      "token",
      "revoke",
      "--state",
      "/state",
      tokRemote.id,
      "--json",
    ]),
  );
  assert.ok(revokeReply.token_ids.includes(tokRemote.id));
  assert.ok(
    revokeReply.disconnected_clients >= 1,
    `expected live attach client to be disconnected on revoke: ${JSON.stringify(revokeReply)}`,
  );

  const attachExit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("attach did not exit after revocation")), 5000);
    attachProc.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
  assert.notEqual(attachExit, 0, "revoked attach session must exit non-zero");

  // Revoked token must now be rejected for new connections.
  assert.throws(() => {
    execFileSync(
      OS_NATIVE_BIN,
      [
        "exec",
        "--target",
        `ws://127.0.0.1:${hostPort}/`,
        "--token",
        tokRemote.token,
        "--",
        "/bin/sh",
        "-c",
        "echo should-fail",
      ],
      { stdio: "pipe" },
    );
  }, "revoked token must be rejected");

  // Container OS itself must remain alive and healthy after client disconnect!
  const infoAfter = await waitForHealthy(cid3, 5000);
  assert.equal(infoAfter.boot_healthy, true);

  podman(["stop", "-t", "10", cid3]);
  podman(["rm", cid3]);
  activeContainers.delete(cid3);

  console.log("[NAT-06] PASS: offline scratch OCI container, persistence, SIGKILL recovery, and remote HostAdapter v2 all verified!");
}

try {
  await main();
} finally {
  cleanup();
}
