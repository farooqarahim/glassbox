# glassbox (Python SDK)

Tamper-evident audit ledger client for AI systems, Python edition.

> **Status:** v0.7-alpha. Mirrors the Rust client surface; no native
> bindings (pure Python over HTTP). The cryptographic primitives stay
> in the Rust core — Python apps never see the signing keys.

## Install

```sh
pip install glassbox
# optional integrations:
pip install glassbox[anthropic]
pip install glassbox[openai]
```

## Quickstart

```python
from glassbox import Client, WalBuffer, wrap_anthropic

with Client("http://glassbox.internal:7878", token="…", stream_id="acme/credit") as gb:
    # health
    assert gb.healthz()

    # verify the chain server-side
    report = gb.verify()
    assert report["ok"]

    # WAL-buffered append for durability under flaky network
    with WalBuffer(gb, path="./wal.jsonl") as wal:
        # sign records server-side via the operator pipeline,
        # then enqueue the signed JSON:
        wal.enqueue(already_signed_record)
```

## Wrap your model client

```python
import anthropic
from glassbox import wrap_anthropic, WalBuffer

raw = anthropic.Anthropic()
wrapped = wrap_anthropic(raw, on_interaction=wal.enqueue_interaction, model_version="20260119")

wrapped.messages.create(model="claude-opus-4-7", messages=[...])
# ↑ every call now produces a Glassbox interaction body that flows
#   into the WAL and on to the ledger.
```

## Run tests

```sh
cargo build --workspace          # one-time, builds glassbox-server
cd sdks/python
pip install -e ".[test]"
pytest -v
```

The pytest fixtures spawn a real `glassbox-server` against a fresh
SQLite ledger so every test exercises the wire protocol end-to-end.
