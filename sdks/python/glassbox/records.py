"""Record-builder dataclasses mirroring the Rust ``glassbox-core``
schema. We hand-define each type here rather than generating from a
.proto so the Python types stay readable and type-checked by mypy/
pyright without code generation.

The shapes are kept byte-identical (key names, optional handling)
with the canonical form Rust produces, so any record built here and
submitted via :class:`~glassbox.client.Client` round-trips through
``Backend::append`` without canonicalisation drift.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContentRef:
    """Content reference per spec §12.2: a hash plus metadata."""

    hash_hex: str
    byte_size: int
    hash_algorithm: str = "SHA-256"
    mime_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "hash_algorithm": self.hash_algorithm,
            "hash_hex": self.hash_hex,
            "byte_size": self.byte_size,
        }
        if self.mime_type is not None:
            out["mime_type"] = self.mime_type
        return out


@dataclass
class ModelFingerprint:
    """Model identity (spec §12.3)."""

    provider: str
    model_name: str
    model_version: str
    sampling: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "provider": self.provider,
            "model_name": self.model_name,
            "model_version": self.model_version,
        }
        if self.sampling is not None:
            out["sampling"] = self.sampling
        return out


@dataclass
class DecisionContext:
    """Business decision metadata (spec §12.1)."""

    decision_id: str
    subject_id: str | None = None
    jurisdiction: str | None = None
    outcome: str | None = None
    automation_level: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"decision_id": self.decision_id}
        if self.subject_id is not None:
            out["subject_id"] = self.subject_id
        if self.jurisdiction is not None:
            out["jurisdiction"] = self.jurisdiction
        if self.outcome is not None:
            out["outcome"] = self.outcome
        if self.automation_level is not None:
            out["automation_level"] = self.automation_level
        return out


@dataclass
class HumanApproval:
    """Human-in-the-loop checkpoint (spec §12.1, Article 14)."""

    approver_id: str
    decision: str  # "approve" | "reject" | "escalate" | "override"
    decided_at: str  # RFC 3339
    rationale_hash_hex: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "approver_id": self.approver_id,
            "decision": self.decision,
            "decided_at": self.decided_at,
        }
        if self.rationale_hash_hex is not None:
            out["rationale_hash_hex"] = self.rationale_hash_hex
        return out


@dataclass
class ToolInvocation:
    """Inline summary of a tool call (spec §12.1)."""

    tool_name: str
    args_hash_hex: str
    success: bool = True
    result_hash_hex: str | None = None
    latency_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool_name": self.tool_name,
            "args_hash_hex": self.args_hash_hex,
            "success": self.success,
        }
        if self.result_hash_hex is not None:
            out["result_hash_hex"] = self.result_hash_hex
        if self.latency_ms is not None:
            out["latency_ms"] = self.latency_ms
        return out


@dataclass
class Tag:
    """Structured tag for query targeting."""

    key: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key, "value": self.value}


@dataclass
class InteractionBody:
    """The payload that gets wrapped in ``RecordBody::Interaction``.

    All optional fields are stripped from the JSON when ``None``,
    matching the Rust ``#[serde(skip_serializing_if = "Option::is_none")]``
    behaviour so canonical-form hashes match across SDKs.
    """

    input: ContentRef | None = None
    output: ContentRef | None = None
    model: ModelFingerprint | None = None
    decision: DecisionContext | None = None
    approval: HumanApproval | None = None
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.input is not None:
            out["input"] = self.input.to_dict()
        if self.output is not None:
            out["output"] = self.output.to_dict()
        if self.model is not None:
            out["model"] = self.model.to_dict()
        if self.decision is not None:
            out["decision"] = self.decision.to_dict()
        if self.approval is not None:
            out["approval"] = self.approval.to_dict()
        if self.tool_calls:
            out["tool_calls"] = [t.to_dict() for t in self.tool_calls]
        if self.tags:
            out["tags"] = [t.to_dict() for t in self.tags]
        if self.metadata:
            out["metadata"] = self.metadata
        return out


def build_interaction(**kwargs: Any) -> InteractionBody:
    """Tiny convenience constructor accepting only the fields a typical
    caller cares about."""
    valid = {f.name for f in dataclasses.fields(InteractionBody)}
    extra = set(kwargs) - valid
    if extra:
        raise TypeError(f"unknown InteractionBody fields: {sorted(extra)}")
    return InteractionBody(**kwargs)
