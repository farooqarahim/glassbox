"""Tests for the `wrap_anthropic` / `wrap_openai` Proxy wrappers.

We don't pull in real `anthropic` / `openai` packages in CI; instead
we hand-roll a tiny fake client that exposes the same
``chat.completions.create`` / ``messages.create`` shape so the wrap
logic can be exercised hermetically.
"""

from glassbox import InteractionBody, wrap_anthropic, wrap_openai


class _FakeCompletionsCreate:
    def __call__(self, **kwargs):
        return {"output_text": f"echoed {kwargs.get('messages', [])}"}


class _FakeChat:
    def __init__(self):
        self.completions = type(
            "C", (), {"create": _FakeCompletionsCreate()}
        )()


class _FakeOpenAI:
    def __init__(self):
        self.chat = _FakeChat()


class _FakeAnthropicMessages:
    def create(self, **kwargs):
        return {"content": "echoed"}


class _FakeAnthropic:
    def __init__(self):
        self.messages = _FakeAnthropicMessages()


def test_wrap_openai_records_each_call():
    captured: list[InteractionBody] = []
    fake = _FakeOpenAI()
    wrapped = wrap_openai(fake, captured.append, model_version="2026-01-19")
    resp = wrapped.chat.completions.create(
        model="gpt-4.1", messages=[{"role": "user", "content": "hi"}]
    )
    assert "echoed" in resp["output_text"]
    assert len(captured) == 1
    body = captured[0].to_dict()
    assert body["model"]["provider"] == "openai"
    assert body["model"]["model_name"] == "gpt-4.1"
    assert body["model"]["model_version"] == "2026-01-19"
    assert "input" in body
    assert "output" in body
    assert len(body["input"]["hash_hex"]) == 64


def test_wrap_anthropic_records_each_call():
    captured: list[InteractionBody] = []
    fake = _FakeAnthropic()
    wrapped = wrap_anthropic(fake, captured.append, model_version="20260119")
    resp = wrapped.messages.create(
        model="claude-opus-4-7", messages=[{"role": "user", "content": "hi"}]
    )
    assert resp == {"content": "echoed"}
    assert len(captured) == 1
    body = captured[0].to_dict()
    assert body["model"]["provider"] == "anthropic"
    assert body["model"]["model_name"] == "claude-opus-4-7"


def test_wrap_passes_through_attributes_unchanged():
    fake = _FakeOpenAI()
    fake.id = "not-intercepted"  # type: ignore[attr-defined]
    wrapped = wrap_openai(fake, lambda _b: None)
    assert wrapped.id == "not-intercepted"


def test_wrap_does_not_break_application_on_audit_failure():
    fake = _FakeOpenAI()

    def boom(_body: InteractionBody) -> None:
        raise RuntimeError("audit pipeline down")

    wrapped = wrap_openai(fake, boom)
    # Must NOT raise — audit failure is non-blocking by design.
    resp = wrapped.chat.completions.create(model="gpt-4.1", messages=[])
    assert "output_text" in resp
