# @glassbox/sdk (TypeScript)

Tamper-evident audit ledger client for AI systems — TypeScript edition.

> **Status:** v0.7-alpha. Mirrors the Python SDK surface, pure
> `fetch`/Node — no native bindings. The cryptographic primitives
> stay in the Rust core; Node apps never see the signing keys.

## Install

```sh
npm install @glassbox/sdk
```

## Quickstart

```ts
import { Client, WalBuffer, wrapOpenAI } from "@glassbox/sdk";

const gb = new Client({
  baseUrl: "http://glassbox.internal:7878",
  token: "…",
  streamId: "acme/credit",
});

console.assert(await gb.healthz());
const report = await gb.verify();
console.assert((report as any).ok);

const wal = await WalBuffer.open(gb, { path: "./wal.jsonl" });
// records are signed by the operator pipeline (Rust CLI); the SDK
// only ships already-signed JSON.
await wal.enqueue(alreadySignedRecord);
await wal.close();
```

## Wrap your model client

```ts
import OpenAI from "openai";
import { wrapOpenAI } from "@glassbox/sdk";

const raw = new OpenAI();
const wrapped = wrapOpenAI(raw, {
  onInteraction: (body) => signAndEnqueue(body),
  modelVersion: "2026-01-19",
});

await wrapped.chat.completions.create({
  model: "gpt-4.1",
  messages: [/* … */],
});
// ↑ every call now produces a Glassbox InteractionBody.
```

## Run tests

```sh
cargo build --workspace          # builds glassbox-server
cd sdks/typescript
npm install
npm test
```

`vitest` spawns a real `glassbox-server` against a fresh SQLite
ledger; every test exercises the wire protocol end-to-end.
