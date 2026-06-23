package glassbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// WrapOptions configures the wrap helpers.
type WrapOptions struct {
	OnInteraction func(InteractionBody)
	ModelVersion  string
}

// BuildInteractionFromCall hashes a (request, response) pair and
// produces an InteractionBody. Go does not have the dynamic SDK
// surface that Python/TS need to proxy through, so the Go SDK exposes
// this primitive directly and lets callers wrap their own HTTP/SDK
// invocations.
//
// Provider must be "anthropic" or "openai" (or whatever string the
// caller wants in the model fingerprint). Model is the model name.
//
// Audit failures never propagate: the callback is invoked inside a
// recover-guarded block.
func BuildInteractionFromCall(
	provider, model, modelVersion string,
	request, response any,
) InteractionBody {
	mv := modelVersion
	if mv == "" {
		mv = "unknown"
	}
	reqJSON := canonicalJSON(request)
	respJSON := canonicalJSON(response)
	return InteractionBody{
		Model: &ModelFingerprint{
			Provider:     provider,
			ModelName:    model,
			ModelVersion: mv,
		},
		Input: &ContentRef{
			HashHex:  sha256Hex(reqJSON),
			ByteSize: uint64(len(reqJSON)),
			MimeType: "application/json",
		},
		Output: &ContentRef{
			HashHex:  sha256Hex(respJSON),
			ByteSize: uint64(len(respJSON)),
			MimeType: "application/json",
		},
	}
}

// WrapCall is a helper for tracing a single AI call:
//
//	body := glassbox.WrapCall(
//	    "openai", "gpt-4.1", "2026-01-19",
//	    request, response,
//	    opts.OnInteraction,
//	)
//
// The callback is invoked synchronously after building the body.
// Panics inside the callback are recovered so audit failures never
// break the calling application (spec §17.2).
func WrapCall(
	provider, model, modelVersion string,
	request, response any,
	onInteraction func(InteractionBody),
) (body InteractionBody) {
	body = BuildInteractionFromCall(provider, model, modelVersion, request, response)
	if onInteraction == nil {
		return body
	}
	defer func() { _ = recover() }()
	onInteraction(body)
	return body
}

func canonicalJSON(value any) []byte {
	// Marshal once to a generic shape, then re-encode with sorted keys.
	raw, err := json.Marshal(value)
	if err != nil {
		return []byte("null")
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return raw
	}
	return mustEncodeSorted(generic)
}

func mustEncodeSorted(v any) []byte {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, _ := json.Marshal(k)
			out = append(out, kb...)
			out = append(out, ':')
			out = append(out, mustEncodeSorted(t[k])...)
		}
		out = append(out, '}')
		return out
	case []any:
		out := []byte{'['}
		for i, item := range t {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, mustEncodeSorted(item)...)
		}
		out = append(out, ']')
		return out
	default:
		b, _ := json.Marshal(v)
		return b
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
