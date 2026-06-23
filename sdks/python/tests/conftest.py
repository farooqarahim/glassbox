"""Test fixtures: spin up a real ``glassbox-server`` against a fresh
SQLite ledger so every test exercises the real wire protocol."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterator

import httpx
import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for(url: str, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=0.5)
            if r.status_code == 200:
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(0.1)
    raise RuntimeError(f"server didn't come up: {url}; last={last_err}")


@pytest.fixture
def server() -> Iterator[dict[str, str]]:
    """Boot ``glassbox-server`` against a fresh ledger + token.
    Yields the base URL and secret for tests to consume."""
    glassbox_bin = REPO_ROOT / "target" / "debug" / "glassbox"
    server_bin = REPO_ROOT / "target" / "debug" / "glassbox-server"
    if not glassbox_bin.exists():
        pytest.skip("cargo build --workspace not run yet — `cargo build` first")
    if not server_bin.exists():
        pytest.skip("glassbox-server binary missing")

    with tempfile.TemporaryDirectory() as tmp:
        tmpp = Path(tmp)
        key = tmpp / "op.key"
        ledger = tmpp / "ledger.db"
        token = tmpp / "tok.json"

        subprocess.run([str(glassbox_bin), "keygen", "--out", str(key)], check=True)
        subprocess.run(
            [
                str(glassbox_bin),
                "init",
                "--ledger",
                str(ledger),
                "--tenant",
                "acme",
                "--system",
                "credit",
                "--key",
                str(key),
            ],
            check=True,
        )
        token.write_text(
            json.dumps(
                {
                    "token_id": "t1",
                    "scope": {
                        "tenant_id": "acme",
                        "stream_id": "acme/credit",
                        "allowed_tools": [],
                        "expires_at": "2099-01-01T00:00:00Z",
                    },
                    "secret": "sssh",
                }
            )
        )
        port = _free_port()
        bind = f"127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                str(server_bin),
                "--ledger",
                str(ledger),
                "--key",
                str(key),
                "--token",
                str(token),
                "--bind",
                bind,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            _wait_for(f"http://{bind}/healthz")
            yield {
                "base_url": f"http://{bind}",
                "secret": "sssh",
                "stream_id": "acme/credit",
                "ledger": str(ledger),
                "key": str(key),
                "glassbox_bin": str(glassbox_bin),
            }
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
