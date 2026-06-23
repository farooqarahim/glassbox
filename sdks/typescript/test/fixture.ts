/**
 * Boots a real `glassbox-server` against a fresh ledger so the SDK
 * tests exercise the real wire protocol.
 */

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import net from "node:net";

const REPO_ROOT = resolve(new URL(".", import.meta.url).pathname, "../../..");

export interface ServerHandle {
  baseUrl: string;
  secret: string;
  streamId: string;
  ledger: string;
  key: string;
  glassboxBin: string;
  stop(): void;
}

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      if (addr && typeof addr === "object") {
        const p = addr.port;
        s.close(() => res(p));
      } else {
        s.close();
        rej(new Error("no port"));
      }
    });
  });
}

async function waitFor(url: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown = null;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch (e) {
      lastErr = e;
    }
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error(`server didn't come up: ${url}; last=${String(lastErr)}`);
}

export async function startServer(): Promise<ServerHandle | null> {
  const glassboxBin = join(REPO_ROOT, "target", "debug", "glassbox");
  const serverBin = join(REPO_ROOT, "target", "debug", "glassbox-server");
  if (!existsSync(glassboxBin) || !existsSync(serverBin)) return null;

  const tmp = mkdtempSync(join(tmpdir(), "glassbox-ts-"));
  const key = join(tmp, "op.key");
  const ledger = join(tmp, "ledger.db");
  const token = join(tmp, "tok.json");

  let r = spawnSync(glassboxBin, ["keygen", "--out", key]);
  if (r.status !== 0) throw new Error(`keygen failed: ${r.stderr.toString()}`);

  r = spawnSync(glassboxBin, [
    "init",
    "--ledger",
    ledger,
    "--tenant",
    "acme",
    "--system",
    "credit",
    "--key",
    key,
  ]);
  if (r.status !== 0) throw new Error(`init failed: ${r.stderr.toString()}`);

  writeFileSync(
    token,
    JSON.stringify({
      token_id: "t1",
      scope: {
        tenant_id: "acme",
        stream_id: "acme/credit",
        allowed_tools: [],
        expires_at: "2099-01-01T00:00:00Z",
      },
      secret: "sssh",
    }),
  );

  const port = await freePort();
  const bind = `127.0.0.1:${port}`;
  const proc: ChildProcess = spawn(
    serverBin,
    [
      "--ledger",
      ledger,
      "--key",
      key,
      "--token",
      token,
      "--bind",
      bind,
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );

  try {
    await waitFor(`http://${bind}/healthz`);
  } catch (e) {
    proc.kill();
    throw e;
  }

  return {
    baseUrl: `http://${bind}`,
    secret: "sssh",
    streamId: "acme/credit",
    ledger,
    key,
    glassboxBin,
    stop: () => {
      proc.kill();
    },
  };
}
