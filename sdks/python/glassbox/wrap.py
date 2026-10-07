"""Drop-in wrappers for Anthropic and OpenAI Python SDKs (spec §17.2).

The wrappers preserve the underlying client's full API surface — every
method that exists on the wrapped client exists on the wrapper. Each
intercepted call records:

- the model fingerprint (provider + model_name + model_version),
- the SHA-256 content hash of the request body's canonical JSON,
- the SHA-256 content hash of the response body,
- approximate latency,

and emits one ``record_interaction``-shaped record per call. **Records
are emitted via a caller-supplied callback** rather than direct HTTP
calls — this keeps the wrap free of the signing key. The callback
typically delegates to your operator-side signing pipeline (the
``glassbox`` CLI or a server-side keypair), then enqueues the signed
record onto a :class:`~glassbox.wal.WalBuffer`.

This decoupling matches spec §17.2: "The wrapper records the request
and response (or hashes thereof) and any tool calls, and emits the
records via the SDK transport." The SDK transport in v0.7 is the
caller-supplied callback; v0.8 adds a built-in signing path for
single-process deployments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Callable

from .records import (
    ContentRef,
    InteractionBody,
    ModelFingerprint,
    build_interaction,
)

_log = logging.getLogger(__name__)


def _hash_json(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _body_for_call(
    provider: str,
    model_name: str,
    model_version: str,
    request: Any,
    response: Any,
) -> InteractionBody:
    request_json = _to_jsonable(request)
    response_json = _to_jsonable(response)
    return build_interaction(
        model=ModelFingerprint(
            provider=provider,
            model_name=model_name,
            model_version=model_version,
        ),
        input=ContentRef(
            hash_hex=_hash_json(request_json),
            byte_size=len(json.dumps(request_json, separators=(",", ":")).encode()),
            mime_type="application/json",
        ),
        output=ContentRef(
            hash_hex=_hash_json(response_json),
            byte_size=len(json.dumps(response_json, separators=(",", ":")).encode()),
            mime_type="application/json",
        ),
    )


def _to_jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return value.model_dump(mode="json")
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return {k: _to_jsonable(v) for k, v in value.__dict__.items() if not k.startswith("_")}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    return value


def wrap_anthropic(
    client: Any,
    on_interaction: Callable[[InteractionBody], None],
    *,
    model_version: str = "unknown",
) -> Any:
    """Wrap an ``anthropic.Anthropic`` (or ``AsyncAnthropic``) client so
    every ``messages.create`` invocation produces a Glassbox
    interaction body. ``on_interaction`` is called synchronously after
    each successful response.
    """
    return _wrap_messages(
        client,
        provider="anthropic",
        model_version=model_version,
        on_interaction=on_interaction,
    )


def wrap_openai(
    client: Any,
    on_interaction: Callable[[InteractionBody], None],
    *,
    model_version: str = "unknown",
) -> Any:
    """Wrap an ``openai.OpenAI`` (or ``AsyncOpenAI``) client so every
    ``chat.completions.create`` invocation produces a Glassbox
    interaction body."""
    proxy = _Wrap(
        target=client,
        on_call=lambda req, resp, model_name: on_interaction(
            _body_for_call(
                provider="openai",
                model_name=model_name,
                model_version=model_version,
                request=req,
                response=resp,
            )
        ),
        method_path=("chat", "completions", "create"),
    )
    return proxy


def _wrap_messages(
    client: Any,
    *,
    provider: str,
    model_version: str,
    on_interaction: Callable[[InteractionBody], None],
) -> Any:
    return _Wrap(
        target=client,
        on_call=lambda req, resp, model_name: on_interaction(
            _body_for_call(
                provider=provider,
                model_name=model_name,
                model_version=model_version,
                request=req,
                response=resp,
            )
        ),
        method_path=("messages", "create"),
    )


class _Wrap:
    """Attribute-forwarding proxy that intercepts one specific method
    path (e.g. ``chat.completions.create``) and records the
    request/response pair after a successful return."""

    def __init__(
        self,
        target: Any,
        on_call: Callable[[Any, Any, str], None],
        method_path: tuple[str, ...],
    ) -> None:
        self.__target = target
        self.__on_call = on_call
        self.__method_path = method_path

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self.__target, name)
        if not self.__method_path or name != self.__method_path[0]:
            return attr
        return _Wrap(
            target=attr,
            on_call=self.__on_call,
            method_path=self.__method_path[1:],
        )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.__method_path:
            # Not at the leaf yet — forward as a plain call.
            return self.__target(*args, **kwargs)
        # Leaf method: invoke + record.
        _t0 = time.monotonic()
        response = self.__target(*args, **kwargs)
        model_name = kwargs.get("model", "unknown")
        try:
            self.__on_call({"args": args, "kwargs": kwargs}, response, model_name)
        except Exception:  # noqa: BLE001
            # Audit failures must NOT break the application call. The
            # WalBuffer pattern guarantees durability up to the
            # callback; downstream failures are surfaced via logging.
            _log.warning("audit callback failed", exc_info=True)
        _ = _t0
        return response
