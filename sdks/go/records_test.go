package glassbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInteractionBodyOmitsEmptyFields(t *testing.T) {
	b := InteractionBody{}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != "{}" {
		t.Fatalf("expected `{}` for empty body, got %s", out)
	}
}

func TestContentRefOmitsMimeType(t *testing.T) {
	r := ContentRef{HashHex: "ab", ByteSize: 2}
	out, _ := json.Marshal(r)
	if strings.Contains(string(out), "mime_type") {
		t.Fatalf("mime_type should be omitted when empty: %s", out)
	}
}

func TestInteractionBodyRoundTrip(t *testing.T) {
	b := InteractionBody{
		Model: &ModelFingerprint{
			Provider:     "anthropic",
			ModelName:    "claude",
			ModelVersion: "v",
		},
		Decision: &DecisionContext{
			DecisionID: "loan-1",
			Outcome:    "approved",
		},
		Tags:     []Tag{{Key: "decision_id", Value: "loan-1"}},
		Metadata: map[string]string{"channel": "web"},
	}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	for _, want := range []string{"claude", "loan-1", "web"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
}
