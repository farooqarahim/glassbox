"""Glassbox — tamper-evident audit ledger client for AI systems.

This package is a thin HTTP client over the ``glassbox-server``
binary's REST surface (spec §15). It does NOT speak gRPC in v0.7
because the gRPC surface needs generated Python code that's hostile
to a hermetic build; that lands in v0.8.

The public surface:

- :class:`Client` — connect, append signed records, query, verify,
  inclusion-proof.
- :class:`WalBuffer` — local disk-backed write-ahead log, per spec
  §16.3. Records persist before the call returns; a background
  flusher ships them to the server.
- :func:`build_interaction` — convenience for building an
  ``InteractionBody`` body shape that the Rust server canonicalizes.
- :func:`wrap_anthropic`, :func:`wrap_openai` — Proxy-style wrappers
  that record every model call and tool invocation transparently
  (spec §17.2).

The Client is **read/append only**. The Glassbox CLI (``glassbox keygen``,
``glassbox init``) handles key management and stream initialisation
out of band — Python apps never see the private keys.
"""

from .client import Client, ClientError
from .records import (
    ContentRef,
    DecisionContext,
    HumanApproval,
    InteractionBody,
    ModelFingerprint,
    Tag,
    ToolInvocation,
    build_interaction,
)
from .wal import WalBuffer
from .wrap import wrap_anthropic, wrap_openai

__version__ = "0.7.0"

__all__ = [
    "Client",
    "ClientError",
    "ContentRef",
    "DecisionContext",
    "HumanApproval",
    "InteractionBody",
    "ModelFingerprint",
    "Tag",
    "ToolInvocation",
    "WalBuffer",
    "build_interaction",
    "wrap_anthropic",
    "wrap_openai",
    "__version__",
]
