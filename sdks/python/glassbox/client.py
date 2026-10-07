"""HTTP client for the ``glassbox-server`` REST surface.

Mirrors the Rust ``Backend`` trait: append, last, get, iter_stream,
list_streams, verify, inclusion-proof. Bearer-token auth. Errors are
mapped to :class:`ClientError` so callers don't need to know about
httpx internals.

The client is sync by default (matches the spec's preference for
simple SDK shapes per §16.1). An async variant is on the v0.8 list;
``httpx.AsyncClient`` is a drop-in replacement once we wire it.
"""

from __future__ import annotations

from typing import Any, cast

import httpx


class ClientError(RuntimeError):
    """Server returned a non-2xx response or the body wouldn't decode."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


class Client:
    """Glassbox HTTP client.

    Parameters
    ----------
    base_url:
        The ``glassbox-server`` base URL, e.g. ``http://127.0.0.1:7878``.
    token:
        The capability-token *secret* the operator issued. Sent in the
        ``Authorization: Bearer …`` header on every authenticated route.
    stream_id:
        The stream this client is scoped to, e.g. ``acme/credit``. Must
        match the token's scope or the server will return 403.
    timeout_seconds:
        Per-request timeout. Defaults to 30s.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        stream_id: str,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._stream = stream_id
        self._http = httpx.Client(
            timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {token}"},
        )

    # context manager: close the underlying connection pool
    def __enter__(self) -> Client:  # noqa: PYI034 — no stdlib Self on py3.9
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying httpx Client."""
        self._http.close()

    # --- health + listing ---

    def healthz(self) -> bool:
        """Return True if the server's ``/healthz`` returns 200."""
        r = httpx.get(f"{self._base}/healthz", timeout=5)
        return r.status_code == 200

    def list_streams(self) -> list[str]:
        """List the streams visible to this token's scope."""
        return cast("list[str]", self._get_json("/v1/streams")["streams"])

    # --- record IO ---

    def last(self) -> dict[str, Any] | None:
        """Return the most recent ``SignedRecord`` on the scoped
        stream, or ``None`` if the stream is empty."""
        body = self._get_json(f"/v1/streams/{_quote(self._stream)}/last")
        if body is None or body == {}:
            return None
        return cast("dict[str, Any]", body)

    def get(self, sequence: int) -> dict[str, Any] | None:
        """Fetch the record at ``sequence`` on the scoped stream."""
        r = self._http.get(
            f"{self._base}/v1/streams/{_quote(self._stream)}/records/{sequence}",
        )
        if r.status_code == 404:
            return None
        _ensure_ok(r)
        return cast("dict[str, Any]", r.json())

    def iter_records(self) -> list[dict[str, Any]]:
        """Return every record on the scoped stream, in sequence order."""
        return cast(
            "list[dict[str, Any]]",
            self._get_json(f"/v1/streams/{_quote(self._stream)}/records"),
        )

    def append(self, signed_record: dict[str, Any]) -> dict[str, Any]:
        """Append a fully-signed record. The Rust side does the
        canonicalisation + signing; this method only ships the JSON
        the operator's signing pipeline already produced."""
        if signed_record.get("record", {}).get("stream_id") != self._stream:
            raise ClientError(
                400,
                f"signed record's stream_id does not match client scope `{self._stream}`",
            )
        r = self._http.post(
            f"{self._base}/v1/streams/{_quote(self._stream)}/append",
            json=signed_record,
        )
        _ensure_ok(r)
        return cast("dict[str, Any]", r.json())

    # --- verification ---

    def verify(self) -> dict[str, Any]:
        """Walk the chain server-side and return a verification report."""
        r = self._http.post(
            f"{self._base}/v1/streams/{_quote(self._stream)}/verify",
        )
        _ensure_ok(r)
        return cast("dict[str, Any]", r.json())

    def inclusion_proof(self, sequence: int) -> dict[str, Any]:
        """Return a Merkle inclusion proof for ``sequence``."""
        r = self._http.post(
            f"{self._base}/v1/streams/{_quote(self._stream)}/inclusion-proof",
            json={"sequence": sequence},
        )
        _ensure_ok(r)
        return cast("dict[str, Any]", r.json())

    # --- helpers ---

    def _get_json(self, path: str) -> Any:
        r = self._http.get(f"{self._base}{path}")
        _ensure_ok(r)
        return cast("dict[str, Any]", r.json())


def _ensure_ok(r: httpx.Response) -> None:
    if r.status_code >= 400:
        raise ClientError(r.status_code, r.text)


def _quote(stream_id: str) -> str:
    """URL-quote the slash in a stream id so axum routes correctly."""
    return stream_id.replace("/", "%2F")
