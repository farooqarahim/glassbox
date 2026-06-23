# glassbox (Go SDK)

Tamper-evident audit ledger client for AI systems — Go edition.

> **Status:** v0.7-alpha. Pure-Go (no cgo, no native bindings). The
> cryptographic primitives stay in the Rust core; Go apps never see
> the signing keys.

## Install

```sh
go get github.com/glassbox/sdk-go
```

## Quickstart

```go
package main

import (
    "context"
    "log"

    glassbox "github.com/glassbox/sdk-go"
)

func main() {
    c := glassbox.NewClient(glassbox.Options{
        BaseURL:  "http://glassbox.internal:7878",
        Token:    "…",
        StreamID: "acme/credit",
    })

    ok, err := c.Healthz(context.Background())
    if err != nil || !ok {
        log.Fatalf("server down: %v", err)
    }

    report, err := c.Verify(context.Background())
    if err != nil {
        log.Fatalf("verify failed: %v", err)
    }
    log.Printf("verify=%v", report["ok"])

    wal, err := glassbox.OpenWal(c, glassbox.WalOptions{Path: "./wal.jsonl"})
    if err != nil {
        log.Fatalf("OpenWal: %v", err)
    }
    defer wal.Close()
    // ship records that were already signed by your operator pipeline
    _ = wal.Enqueue(alreadySignedRecord)
}
```

## Tracing a model call

```go
body := glassbox.WrapCall(
    "openai", "gpt-4.1", "2026-01-19",
    request, response,
    func(b glassbox.InteractionBody) { signAndEnqueue(b) },
)
_ = body
```

## Run tests

```sh
cargo build --workspace
cd sdks/go
go test ./...
```

`go test` spawns a real `glassbox-server` against a fresh SQLite
ledger; every test exercises the wire protocol end-to-end.
