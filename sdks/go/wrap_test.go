package glassbox

import (
	"strings"
	"testing"
)

func TestWrapCallProducesInteractionBody(t *testing.T) {
	captured := []InteractionBody{}
	body := WrapCall(
		"openai", "gpt-4.1", "2026-01-19",
		map[string]any{"messages": []any{map[string]any{"role": "user", "content": "hi"}}},
		map[string]any{"output_text": "echoed"},
		func(b InteractionBody) { captured = append(captured, b) },
	)
	if body.Model == nil || body.Model.Provider != "openai" {
		t.Fatalf("expected provider=openai, got %+v", body.Model)
	}
	if body.Model.ModelName != "gpt-4.1" {
		t.Fatalf("expected model_name=gpt-4.1, got %s", body.Model.ModelName)
	}
	if body.Model.ModelVersion != "2026-01-19" {
		t.Fatalf("expected model_version=2026-01-19, got %s", body.Model.ModelVersion)
	}
	if body.Input == nil || len(body.Input.HashHex) != 64 {
		t.Fatalf("expected 64-char input hash, got %+v", body.Input)
	}
	if body.Output == nil || len(body.Output.HashHex) != 64 {
		t.Fatalf("expected 64-char output hash, got %+v", body.Output)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 captured body, got %d", len(captured))
	}
}

func TestWrapCallDoesNotPanicIfCallbackPanics(t *testing.T) {
	body := WrapCall(
		"anthropic", "claude-opus-4-7", "20260119",
		map[string]any{"messages": []any{}},
		map[string]any{"content": "echoed"},
		func(_ InteractionBody) { panic("audit pipeline down") },
	)
	if body.Model == nil || body.Model.Provider != "anthropic" {
		t.Fatalf("expected provider=anthropic, got %+v", body.Model)
	}
}

func TestCanonicalJSONIsKeySorted(t *testing.T) {
	a := canonicalJSON(map[string]any{"b": 1, "a": 2})
	b := canonicalJSON(map[string]any{"a": 2, "b": 1})
	if string(a) != string(b) {
		t.Fatalf("canonical JSON not key-sorted: %s vs %s", a, b)
	}
	if !strings.HasPrefix(string(a), `{"a":`) {
		t.Fatalf("expected sorted order; got %s", a)
	}
}
