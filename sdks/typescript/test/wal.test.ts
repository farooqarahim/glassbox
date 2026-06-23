import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client, WalBuffer } from "../src/index.js";
import { startServer, type ServerHandle } from "./fixture.js";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

let srv: ServerHandle | null = null;

beforeAll(async () => {
  srv = await startServer();
});

afterAll(() => {
  srv?.stop();
});

describe("WalBuffer", () => {
  it("retains records when the server rejects them", async () => {
    if (!srv) return;

    // Sign + commit a record via the CLI, then read it back.
    const tmp = mkdtempSync(join(tmpdir(), "glassbox-walbody-"));
    const bodyPath = join(tmp, "body.json");
    writeFileSync(
      bodyPath,
      JSON.stringify({
        model: {
          provider: "anthropic",
          model_name: "claude-opus-4-7",
          model_version: "v",
        },
        tags: [{ key: "decision_id", value: "wal-ts" }],
      }),
    );
    const r = spawnSync(srv.glassboxBin, [
      "append",
      "--ledger",
      srv.ledger,
      "--stream",
      srv.streamId,
      "--key",
      srv.key,
      "--body",
      bodyPath,
    ]);
    if (r.status !== 0) throw new Error(`append failed: ${r.stderr.toString()}`);

    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    const signed = await c.last();
    expect(signed).not.toBeNull();

    const walPath = join(tmp, "wal.jsonl");
    const wal = await WalBuffer.open(c, { path: walPath, flushIntervalMs: 100 });
    await wal.enqueue(signed!);
    // Give the flusher 1s to ATTEMPT delivery; the server will reject
    // because the same sequence is already committed.
    await new Promise((res) => setTimeout(res, 1_000));
    await wal.close();

    const pending = readFileSync(walPath, "utf-8")
      .split("\n")
      .filter((l) => l.trim());
    expect(pending.length).toBe(1);
  });

  it("flush on an empty buffer is a no-op", async () => {
    if (!srv) return;
    const tmp = mkdtempSync(join(tmpdir(), "glassbox-walempty-"));
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    const wal = await WalBuffer.open(c, {
      path: join(tmp, "wal.jsonl"),
      flushIntervalMs: 50,
    });
    await wal.flush(1_000);
    expect(wal.pending()).toBe(0);
    await wal.close();
  });
});

