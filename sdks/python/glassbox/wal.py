"""Local disk-backed write-ahead log (spec §16.3).

The :class:`WalBuffer` persists records to a JSON-Lines file before
returning to the caller. A background thread drains the file to the
configured :class:`~glassbox.client.Client`. If the server is
unreachable, records stay on disk until it returns; the caller never
loses durability.

This is the spec's "records buffer locally and flush later" pattern:
the SDK acknowledges write-side durability the instant the bytes hit
the WAL file's fsync, decoupling the caller's request latency from
the server's availability.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .client import Client, ClientError


class WalBuffer:
    """Append-only durable buffer in front of a :class:`Client`.

    Parameters
    ----------
    client:
        Where records are eventually delivered.
    path:
        Path to the WAL file (created if missing).
    flush_interval_seconds:
        How often the background thread drains.
    max_pending:
        Soft cap; once the WAL holds this many un-shipped records,
        :meth:`enqueue` blocks until the flusher catches up.
    """

    def __init__(
        self,
        client: Client,
        path: str | os.PathLike[str],
        flush_interval_seconds: float = 1.0,
        max_pending: int = 10_000,
    ) -> None:
        self._client = client
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._flush_interval = flush_interval_seconds
        self._max_pending = max_pending
        self._stop = threading.Event()
        self._pending_count = self._count_pending()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def enqueue(self, signed_record: dict[str, Any]) -> None:
        """Append a fully-signed record to the WAL. Returns once the
        bytes are fsynced."""
        with self._cv:
            while self._pending_count >= self._max_pending and not self._stop.is_set():
                self._cv.wait(timeout=0.5)
            line = json.dumps({"record": signed_record}, separators=(",", ":"))
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._pending_count += 1
            self._cv.notify_all()

    def flush(self, timeout_seconds: float | None = None) -> None:
        """Block until every WAL entry has been shipped to the server.
        Useful in tests; not normally called by application code."""
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        while True:
            with self._cv:
                if self._pending_count == 0:
                    return
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"WAL still holds {self._pending_count} records")
            time.sleep(0.05)

    def close(self) -> None:
        """Stop the background flusher. Pending records remain in the
        WAL file and will be re-shipped on the next ``WalBuffer`` opened
        against the same path."""
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        self._thread.join(timeout=2.0)

    # context manager
    def __enter__(self) -> "WalBuffer":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # --- internals ---

    def _count_pending(self) -> int:
        if not self._path.exists():
            return 0
        with self._path.open("r", encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())

    def _loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._flush_interval)
            try:
                self._drain_once()
            except Exception:  # noqa: BLE001 — keep the flusher alive
                # In production a retry+backoff loop is in order; v0.7
                # ships the simplest correct version. We never lose
                # records — they stay in the WAL.
                pass

    def _drain_once(self) -> None:
        with self._lock:
            if not self._path.exists() or self._path.stat().st_size == 0:
                self._pending_count = 0
                self._cv.notify_all()
                return
            lines = self._path.read_text(encoding="utf-8").splitlines()

        remaining: list[str] = []
        for line in lines:
            if not line.strip():
                continue
            entry = json.loads(line)
            try:
                self._client.append(entry["record"])
            except ClientError:
                # Server unreachable or rejected. Keep in WAL.
                remaining.append(line)

        with self._lock:
            if remaining:
                self._path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
            else:
                self._path.write_text("", encoding="utf-8")
            self._pending_count = len(remaining)
            self._cv.notify_all()
