package glassbox

import (
	"encoding/json"
	"errors"
)

// ContentRef is a hash reference to a byte payload stored elsewhere.
type ContentRef struct {
	HashHex  string `json:"hash_hex"`
	ByteSize uint64 `json:"byte_size"`
	MimeType string `json:"mime_type,omitempty"`
}

// ModelFingerprint identifies an upstream model and its version.
type ModelFingerprint struct {
	Provider     string `json:"provider"`
	ModelName    string `json:"model_name"`
	ModelVersion string `json:"model_version"`
}

// DecisionContext describes a downstream decision that depended on the interaction.
type DecisionContext struct {
	DecisionID string `json:"decision_id"`
	Outcome    string `json:"outcome"`
	SchemaURI  string `json:"schema_uri,omitempty"`
}

// HumanApproval captures a human-in-the-loop sign-off.
type HumanApproval struct {
	ApproverID string `json:"approver_id"`
	Decision   string `json:"decision"`
	DecidedAt  string `json:"decided_at"`
	Note       string `json:"note,omitempty"`
}

// ToolInvocation records an opaque tool/MCP call hash-pair.
type ToolInvocation struct {
	ToolName      string `json:"tool_name"`
	ArgsHashHex   string `json:"args_hash_hex"`
	ResultHashHex string `json:"result_hash_hex"`
}

// Tag is a free-form (key, value) label.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// InteractionBody mirrors the Rust `InteractionBody` JSON shape. All
// optional fields are pointer types so JSON encoding emits them only
// when set (matching `Option::is_none` skip behavior).
type InteractionBody struct {
	Model     *ModelFingerprint `json:"model,omitempty"`
	Input     *ContentRef       `json:"input,omitempty"`
	Output    *ContentRef       `json:"output,omitempty"`
	Decision  *DecisionContext  `json:"decision,omitempty"`
	Approval  *HumanApproval    `json:"approval,omitempty"`
	ToolCalls []ToolInvocation  `json:"tool_calls,omitempty"`
	Tags      []Tag             `json:"tags,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MarshalJSON ensures we never emit zero-value substructs.
func (b InteractionBody) MarshalJSON() ([]byte, error) {
	type alias InteractionBody
	return json.Marshal(alias(b))
}

// ErrUnknownField is returned by BuildInteraction when an option
// references a field that does not exist on InteractionBody.
var ErrUnknownField = errors.New("unknown InteractionBody field")
