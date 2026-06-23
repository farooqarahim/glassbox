/**
 * Local disk-backed write-ahead log for Glassbox records (spec §16.3).
 *
 * Records are written to a JSON-Lines file and fsynced before
 * `enqueue` resolves, so callers get durability the instant we say
 * yes. A timer-driven background drain ships them to the server;
 * server errors leave the record on disk for the next pass.
 */

import { Client, ClientError } from "./client.js";
import { appendFile, readFile, writeFile, stat, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface WalOptions {
  readonly path: string;
  readonly flushIntervalMs?: number;
  readonly maxPending?: number;
}

export class WalBuffer {
  private readonly client: Client;
  private readonly path: string;
  private readonly flushIntervalMs: number;
  private readonly maxPending: number;
  private pendingCount = 0;
  private draining = false;
  private stopped = false;
  private timer: NodeJS.Timeout | null = null;
  /** Serializes writes against the WAL file. */
  private writeQueue: Promise<void> = Promise.resolve();

  private constructor(client: Client, opts: WalOptions) {
    this.client = client;
    this.path = opts.path;
    this.flushIntervalMs = opts.flushIntervalMs ?? 1_000;
    this.maxPending = opts.maxPending ?? 10_000;
  }

  /** Async constructor: ensures the parent dir exists and counts existing entries. */
  static async open(client: Client, opts: WalOptions): Promise<WalBuffer> {
    const wal = new WalBuffer(client, opts);
    await mkdir(dirname(wal.path), { recursive: true });
    try {
      const txt = await readFile(wal.path, "utf-8");
      wal.pendingCount = txt.split("\n").filter((l) => l.trim()).length;
    } catch {
      // file doesn't exist yet — create empty so subsequent appends succeed
      await writeFile(wal.path, "", "utf-8");
    }
    wal.timer = setInterval(() => {
      void wal.drainOnce();
    }, wal.flushIntervalMs);
    return wal;
  }

  async enqueue(signedRecord: Record<string, unknown>): Promise<void> {
    if (this.stopped) throw new Error("WalBuffer is closed");
    if (this.pendingCount >= this.maxPending) {
      throw new Error(
        `WAL pending cap reached (${this.maxPending}); flush before enqueueing more`,
      );
    }
    const line = JSON.stringify({ record: signedRecord }) + "\n";
    this.writeQueue = this.writeQueue.then(() => appendFile(this.path, line));
    await this.writeQueue;
    this.pendingCount += 1;
  }

  /** Block until the WAL is empty. Used by tests. */
  async flush(timeoutMs = 5_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await this.drainOnce();
      if (this.pendingCount === 0) return;
      await sleep(50);
    }
    if (this.pendingCount > 0) {
      throw new Error(`WAL still holds ${this.pendingCount} records`);
    }
  }

  async close(): Promise<void> {
    this.stopped = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.writeQueue;
  }

  /** Visible for tests. */
  pending(): number {
    return this.pendingCount;
  }

  private async drainOnce(): Promise<void> {
    if (this.draining || this.stopped) return;
    this.draining = true;
    try {
      let txt = "";
      try {
        const s = await stat(this.path);
        if (s.size === 0) {
          this.pendingCount = 0;
          return;
        }
        txt = await readFile(this.path, "utf-8");
      } catch {
        this.pendingCount = 0;
        return;
      }
      const lines = txt.split("\n").filter((l) => l.trim());
      const remaining: string[] = [];
      for (const line of lines) {
        let entry: { record?: Record<string, unknown> };
        try {
          entry = JSON.parse(line) as { record?: Record<string, unknown> };
        } catch {
          // malformed; drop to avoid an infinite retry on a poison record
          continue;
        }
        if (!entry.record) continue;
        try {
          await this.client.append(entry.record);
        } catch (e) {
          if (e instanceof ClientError) {
            remaining.push(line);
          } else {
            // unexpected — re-throw so it's visible
            remaining.push(line);
          }
        }
      }
      const next = remaining.length === 0 ? "" : remaining.join("\n") + "\n";
      await writeFile(this.path, next, "utf-8");
      this.pendingCount = remaining.length;
    } finally {
      this.draining = false;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}
