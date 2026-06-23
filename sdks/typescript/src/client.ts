/**
 * Glassbox HTTP client (TypeScript).
 *
 * Pure `fetch` — no third-party HTTP dependency. The Rust core
 * canonicalises and signs records; this client only ships already-
 * signed JSON over the wire.
 */

export class ClientError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string) {
    super(`HTTP ${status}: ${body}`);
    this.name = "ClientError";
    this.status = status;
    this.body = body;
  }
}

export interface ClientOptions {
  readonly baseUrl: string;
  readonly token: string;
  readonly streamId: string;
  readonly timeoutMs?: number;
  /** Optional injection seam for tests; defaults to global fetch. */
  readonly fetch?: typeof fetch;
}

export class Client {
  private readonly base: string;
  private readonly token: string;
  private readonly stream: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.stream = opts.streamId;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async healthz(): Promise<boolean> {
    const r = await this.req("GET", "/healthz", undefined, /*auth*/ false);
    return r.ok;
  }

  async listStreams(): Promise<string[]> {
    const body = await this.json("GET", "/v1/streams");
    return (body as { streams: string[] }).streams;
  }

  async last(): Promise<Record<string, unknown> | null> {
    const path = `/v1/streams/${quote(this.stream)}/last`;
    const r = await this.req("GET", path);
    if (r.status === 404) return null;
    await ensureOk(r);
    const body = (await r.json()) as Record<string, unknown> | null;
    if (body === null || Object.keys(body).length === 0) return null;
    return body;
  }

  async get(sequence: number): Promise<Record<string, unknown> | null> {
    const path = `/v1/streams/${quote(this.stream)}/records/${sequence}`;
    const r = await this.req("GET", path);
    if (r.status === 404) return null;
    await ensureOk(r);
    return (await r.json()) as Record<string, unknown>;
  }

  async iterRecords(): Promise<Record<string, unknown>[]> {
    const path = `/v1/streams/${quote(this.stream)}/records`;
    return (await this.json("GET", path)) as Record<string, unknown>[];
  }

  async append(
    signedRecord: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const inner = (signedRecord["record"] ?? {}) as Record<string, unknown>;
    if (inner["stream_id"] !== this.stream) {
      throw new ClientError(
        400,
        `signed record's stream_id does not match client scope \`${this.stream}\``,
      );
    }
    const path = `/v1/streams/${quote(this.stream)}/append`;
    return (await this.json("POST", path, signedRecord)) as Record<
      string,
      unknown
    >;
  }

  async verify(): Promise<Record<string, unknown>> {
    const path = `/v1/streams/${quote(this.stream)}/verify`;
    return (await this.json("POST", path)) as Record<string, unknown>;
  }

  async inclusionProof(sequence: number): Promise<Record<string, unknown>> {
    const path = `/v1/streams/${quote(this.stream)}/inclusion-proof`;
    return (await this.json("POST", path, { sequence })) as Record<
      string,
      unknown
    >;
  }

  // --- internals ---

  private async json(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const r = await this.req(method, path, body);
    await ensureOk(r);
    return await r.json();
  }

  private async req(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    auth = true,
  ): Promise<Response> {
    const headers: Record<string, string> = {};
    if (auth) headers["Authorization"] = `Bearer ${this.token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(`${this.base}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(t);
    }
  }
}

async function ensureOk(r: Response): Promise<void> {
  if (r.status >= 400) {
    const text = await r.text();
    throw new ClientError(r.status, text);
  }
}

function quote(streamId: string): string {
  return streamId.replace(/\//g, "%2F");
}
