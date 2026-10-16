"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { randomBytes } = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

for (const signal of ["SIGTERM", "SIGINT"]) {
  test(`${signal} during analytics initialization cannot start HTTP after shutdown begins`, { timeout: 10000 }, async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "analytics-startup-stop-"));
    const child = spawn(process.execPath, ["-e", `
      const Module = require('node:module');
      const originalLoad = Module._load;
      Module._load = function(request, parent, isMain) {
        if (request.endsWith('/analyticsCheckpointStore.js')) return function delayedCheckpoint() {
          return { ready: new Promise(resolve => setTimeout(() => resolve(true), 600)),
            getData: () => null, getStatus: () => ({ready: true, pending: 0, lastSaveAt: null, lastError: null}),
            save: async () => true, flush: async () => true, close: async () => true };
        };
        return originalLoad.call(this, request, parent, isMain);
      };
      const http = require('node:http');
      const originalListen = http.Server.prototype.listen;
      http.Server.prototype.listen = function(...args) {
        process.send({ type: 'listen_called' });
        return originalListen.apply(this, args);
      };
      globalThis.fetch = async () => { throw new Error('isolated startup fixture blocks upstream HTTP'); };
      require('./server.js');
      process.send({ type: 'initializing' });
    `], {
      cwd: path.resolve(__dirname, ".."),
      env: { PATH: process.env.PATH, NODE_ENV: "development", PORT: "0",
        AES_KEY_HEX: randomBytes(32).toString("hex"), ADMIN_TOKEN: randomBytes(32).toString("hex"),
        TURNSTILE_SITEKEY: "1x00000000000000000000AA", TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
        DEBUG_SHOW_KEYS_ON_START: "0", DEBUG_ALLOW_PLAINTEXT_KEYS: "0", LOG_TO_FILE: "0",
        ANALYTICS_STORAGE_DIR: path.join(directory, "analytics"), RUNTIME_DIAG_DIR: directory,
        IPINFO_LITE_ENABLED: "0", RISK_IP_INTELLIGENCE_ENABLED: "0", SHUTDOWN_GRACE_MS: "2000" },
      stdio: ["ignore", "ignore", "ignore", "ipc"]
    });
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) { const exit = once(child, "exit"); child.kill("SIGKILL"); await exit; }
      await fs.rm(directory, { recursive: true, force: true });
    });
    const messages = [];
    child.on("message", message => messages.push(message.type));
    const exit = once(child, "exit");
    while (!messages.includes("initializing")) {
      assert.equal(child.exitCode, null);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    child.kill(signal);
    const [code, exitSignal] = await exit;
    assert.equal(code, 0);
    assert.equal(exitSignal, null);
    assert.deepEqual(messages, ["initializing"], "no listener or server startup timers may start during cleanup");
  });
}
