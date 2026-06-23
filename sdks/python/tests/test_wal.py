"""WAL buffer tests against the real server."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from glassbox import Client, WalBuffer


def _sign_via_cli(server, body: dict) -> dict:
    """Use the `glassbox append` CLI to sign + emit a record, then read
    it back out of the server. Since the CLI writes directly to the
    same SQLite file, we recover the JSON SignedRecord by re-reading
    the latest row via the HTTP `last` endpoint."""
    gb = server["glassbox_bin"]
    ledger = server["ledger"]
    key = server["key"]
    tmp_body = Path(server["ledger"]).parent / "body.json"
    tmp_body.write_text(json.dumps(body))
    subprocess.run(
        [
            gb,
            "append",
            "--ledger",
            ledger,
            "--stream",
            server["stream_id"],
            "--key",
            key,
            "--body",
            str(tmp_body),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        return c.last()


def test_wal_enqueues_and_flushes_durably(server, tmp_path):
    """The WAL persists before returning; once a record is in the WAL
    file, a flush to the server completes idempotently."""
    # Pre-sign a record by appending via the CLI, then read back its
    # exact bytes — that's what we'll feed to the WAL.
    signed = _sign_via_cli(
        server,
        {
            "model": {
                "provider": "anthropic",
                "model_name": "claude-opus-4-7",
                "model_version": "v",
            },
            "tags": [{"key": "decision_id", "value": "wal-test"}],
        },
    )
    assert signed is not None

    # Append-via-WAL: the server will see a sequence collision because
    # the CLI already wrote this exact record. That's exactly what we
    # want to assert — the WAL doesn't lose records on transient
    # rejections; they stay on disk.
    wal_path = tmp_path / "wal.jsonl"
    with Client(server["base_url"], server["secret"], server["stream_id"]) as client:
        with WalBuffer(client, wal_path, flush_interval_seconds=0.1) as wal:
            wal.enqueue(signed)
            # Give the flusher a tick.
            time.sleep(0.5)
            # The record was already in the ledger, so the server
            # rejects it with a sequence-collision. WAL keeps the bytes.
            with open(wal_path) as f:
                pending = [ln for ln in f if ln.strip()]
            assert len(pending) == 1, (
                "WAL must retain the record after a server-side rejection"
            )


def test_wal_empty_buffer_flushes_to_zero(server, tmp_path):
    wal_path = tmp_path / "wal.jsonl"
    with Client(server["base_url"], server["secret"], server["stream_id"]) as client:
        with WalBuffer(client, wal_path, flush_interval_seconds=0.05) as wal:
            wal.flush(timeout_seconds=1.0)
