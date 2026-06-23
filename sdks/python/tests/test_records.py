"""Unit tests for record builders. Hermetic — no server required."""

import json

from glassbox import (
    ContentRef,
    DecisionContext,
    HumanApproval,
    ModelFingerprint,
    Tag,
    ToolInvocation,
    build_interaction,
)


def test_content_ref_omits_optional_mime_type():
    body = ContentRef(hash_hex="ab", byte_size=2).to_dict()
    assert "mime_type" not in body


def test_interaction_body_drops_empty_fields():
    body = build_interaction().to_dict()
    assert body == {}


def test_interaction_body_round_trips():
    body = build_interaction(
        model=ModelFingerprint(
            provider="anthropic", model_name="claude", model_version="v"
        ),
        decision=DecisionContext(decision_id="loan-1", outcome="approved"),
        approval=HumanApproval(
            approver_id="r1", decision="approve", decided_at="2026-05-13T12:00:00Z"
        ),
        tool_calls=[
            ToolInvocation(
                tool_name="search", args_hash_hex="aa", result_hash_hex="bb"
            )
        ],
        tags=[Tag(key="decision_id", value="loan-1")],
        metadata={"channel": "web"},
    ).to_dict()

    encoded = json.dumps(body, sort_keys=True)
    assert "claude" in encoded
    assert "approve" in encoded
    assert "loan-1" in encoded
    assert "search" in encoded


def test_unknown_field_in_build_interaction_is_rejected():
    try:
        build_interaction(not_a_field=42)
    except TypeError as e:
        assert "not_a_field" in str(e)
    else:
        raise AssertionError("expected TypeError")
