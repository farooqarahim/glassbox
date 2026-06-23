import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client, ClientError } from "../src/index.js";
import { startServer, type ServerHandle } from "./fixture.js";

let srv: ServerHandle | null = null;

beforeAll(async () => {
  srv = await startServer();
});

afterAll(() => {
  srv?.stop();
});

describe("Client", () => {
  it("healthz returns true on a live server", async () => {
    if (!srv) return; // server binary missing — skip
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    expect(await c.healthz()).toBe(true);
  });

  it("lists the scoped stream", async () => {
    if (!srv) return;
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    expect(await c.listStreams()).toEqual(["acme/credit"]);
  });

  it("returns the genesis record on iter", async () => {
    if (!srv) return;
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    const rs = await c.iterRecords();
    expect(rs.length).toBe(1);
    const first = rs[0]!;
    const rec = first["record"] as { sequence: number };
    expect(rec.sequence).toBe(0);
  });

  it("returns an inclusion proof for the genesis record", async () => {
    if (!srv) return;
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    const proof = (await c.inclusionProof(0)) as {
      leaf_hex: string;
      root_hex: string;
      steps: unknown[];
    };
    expect(proof.leaf_hex.length).toBe(64);
    expect(proof.root_hex.length).toBe(64);
    expect(proof.steps).toEqual([]);
  });

  it("verifies the chain server-side", async () => {
    if (!srv) return;
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    const r = (await c.verify()) as { ok: boolean; records_walked: number };
    expect(r.ok).toBe(true);
    expect(r.records_walked).toBe(1);
  });

  it("rejects a wrong token with 401/403", async () => {
    if (!srv) return;
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: "wrong-secret",
      streamId: srv.streamId,
    });
    let caught: unknown = null;
    try {
      await c.listStreams();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ClientError);
    expect([401, 403]).toContain((caught as ClientError).status);
  });

  it("returns null for a missing sequence", async () => {
    if (!srv) return;
    const c = new Client({
      baseUrl: srv.baseUrl,
      token: srv.secret,
      streamId: srv.streamId,
    });
    expect(await c.get(9999)).toBeNull();
  });
});
