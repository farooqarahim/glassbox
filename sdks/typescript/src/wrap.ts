/**
 * Proxy wrappers for OpenAI/Anthropic Node SDKs (spec §17.2).
 *
 * The wrapper intercepts a single method path (e.g.
 * `chat.completions.create` for OpenAI, `messages.create` for
 * Anthropic) and emits one `InteractionBody` per call via the
 * caller-supplied callback. The original client's full surface is
 * preserved via `Proxy` attribute forwarding.
 *
 * Audit failures never break the application call.
 */

import { createHash } from "node:crypto";
import { buildInteraction, type InteractionBody } from "./records.js";

export interface WrapOptions {
  readonly onInteraction: (body: InteractionBody) => void | Promise<void>;
  readonly modelVersion?: string;
}

export function wrapOpenAI<T extends object>(client: T, opts: WrapOptions): T {
  return wrapMethodPath(
    client,
    ["chat", "completions", "create"] as const,
    "openai",
    opts,
  );
}

export function wrapAnthropic<T extends object>(
  client: T,
  opts: WrapOptions,
): T {
  return wrapMethodPath(client, ["messages", "create"] as const, "anthropic", opts);
}

function wrapMethodPath<T extends object>(
  client: T,
  path: readonly string[],
  provider: string,
  opts: WrapOptions,
): T {
  return buildProxy(client, path, provider, opts);
}

function buildProxy<T extends object>(
  target: T,
  remaining: readonly string[],
  provider: string,
  opts: WrapOptions,
): T {
  if (remaining.length === 0) {
    // Leaf: intercept calls
    if (typeof target !== "function") return target;
    const fn = target as unknown as (...args: unknown[]) => unknown;
    const wrapped = function (this: unknown, ...args: unknown[]) {
      const result = fn.apply(this, args);
      if (result && typeof (result as Promise<unknown>).then === "function") {
        return (result as Promise<unknown>).then((resp) => {
          emit(args, resp, provider, opts);
          return resp;
        });
      }
      emit(args, result, provider, opts);
      return result;
    };
    return wrapped as unknown as T;
  }
  return new Proxy(target, {
    get(t, prop, recv) {
      const value = Reflect.get(t, prop, recv);
      if (prop !== remaining[0]) return value;
      if (value === undefined || value === null) return value;
      // Bind methods to their original `this` so the SDK keeps working.
      const bound =
        typeof value === "function"
          ? (value as (...a: unknown[]) => unknown).bind(t)
          : value;
      return buildProxy(
        bound as object,
        remaining.slice(1),
        provider,
        opts,
      );
    },
  }) as T;
}

function emit(
  args: readonly unknown[],
  response: unknown,
  provider: string,
  opts: WrapOptions,
): void {
  try {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const modelName =
      typeof kwargs["model"] === "string" ? (kwargs["model"] as string) : "unknown";
    const reqJson = canonicalize({ args });
    const respJson = canonicalize(response);
    const body = buildInteraction({
      model: {
        provider,
        model_name: modelName,
        model_version: opts.modelVersion ?? "unknown",
      },
      input: {
        hash_hex: sha256Hex(reqJson),
        byte_size: Buffer.byteLength(reqJson, "utf-8"),
        mime_type: "application/json",
      },
      output: {
        hash_hex: sha256Hex(respJson),
        byte_size: Buffer.byteLength(respJson, "utf-8"),
        mime_type: "application/json",
      },
    });
    const r = opts.onInteraction(body);
    if (r && typeof (r as Promise<void>).catch === "function") {
      (r as Promise<void>).catch(() => {
        /* swallow */
      });
    }
  } catch {
    // Audit failures are non-blocking by design (spec §17.2).
  }
}

function canonicalize(value: unknown): string {
  // Stable key order matters for the hash.
  return JSON.stringify(value, (_k, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const o = v as Record<string, unknown>;
      return Object.keys(o)
        .sort()
        .reduce<Record<string, unknown>>((acc, k) => {
          acc[k] = o[k];
          return acc;
        }, {});
    }
    return v;
  });
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf-8").digest("hex");
}
