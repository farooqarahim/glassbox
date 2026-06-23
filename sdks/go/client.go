// Package glassbox is the Go SDK for Glassbox, a tamper-evident audit
// ledger for AI systems.
//
// The Client wraps the glassbox-server HTTP surface. The Rust core
// canonicalises and signs records server-side; this SDK only ships
// already-signed JSON.
package glassbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ClientError is returned when the server responds with a non-2xx
// status or when the response cannot be decoded.
type ClientError struct {
	Status int
	Body   string
}

func (e *ClientError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

// Client is the Glassbox HTTP client. Construct one with NewClient.
// Safe for concurrent use across goroutines.
type Client struct {
	baseURL    string
	token      string
	streamID   string
	httpClient *http.Client
}

// Options configures a Client.
type Options struct {
	BaseURL  string
	Token    string
	StreamID string
	// Timeout is the per-request timeout. Defaults to 30s.
	Timeout time.Duration
	// HTTPClient is an optional override (useful for tests).
	HTTPClient *http.Client
}

// NewClient returns a Glassbox client.
func NewClient(opts Options) *Client {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}
	return &Client{
		baseURL:    strings.TrimRight(opts.BaseURL, "/"),
		token:      opts.Token,
		streamID:   opts.StreamID,
		httpClient: hc,
	}
}

// Healthz returns true if the server's /healthz endpoint reports OK.
func (c *Client) Healthz(ctx context.Context) (bool, error) {
	r, err := c.do(ctx, http.MethodGet, "/healthz", nil, false)
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
	return r.StatusCode == http.StatusOK, nil
}

// ListStreams returns the streams visible to this token.
func (c *Client) ListStreams(ctx context.Context) ([]string, error) {
	var out struct {
		Streams []string `json:"streams"`
	}
	if err := c.getJSON(ctx, "/v1/streams", &out); err != nil {
		return nil, err
	}
	return out.Streams, nil
}

// Last returns the most recent SignedRecord on the scoped stream, or
// nil if the stream is empty.
func (c *Client) Last(ctx context.Context) (map[string]any, error) {
	r, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/streams/%s/last", quote(c.streamID)), nil, true)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := ensureOK(r); err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}
	return body, nil
}

// Get fetches the record at the given sequence on the scoped stream.
// Returns (nil, nil) if no such record exists.
func (c *Client) Get(ctx context.Context, sequence int64) (map[string]any, error) {
	path := fmt.Sprintf("/v1/streams/%s/records/%d", quote(c.streamID), sequence)
	r, err := c.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := ensureOK(r); err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}

// IterRecords returns every record on the scoped stream in sequence order.
func (c *Client) IterRecords(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	path := fmt.Sprintf("/v1/streams/%s/records", quote(c.streamID))
	if err := c.getJSON(ctx, path, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Append ships a fully-signed record to the server. The signed_record
// argument must have the shape produced by the Rust signing pipeline.
func (c *Client) Append(ctx context.Context, signedRecord map[string]any) (map[string]any, error) {
	inner, _ := signedRecord["record"].(map[string]any)
	if streamID, _ := inner["stream_id"].(string); streamID != c.streamID {
		return nil, &ClientError{
			Status: http.StatusBadRequest,
			Body:   fmt.Sprintf("signed record's stream_id does not match client scope %q", c.streamID),
		}
	}
	path := fmt.Sprintf("/v1/streams/%s/append", quote(c.streamID))
	var out map[string]any
	if err := c.postJSON(ctx, path, signedRecord, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Verify walks the chain server-side and returns the verification report.
func (c *Client) Verify(ctx context.Context) (map[string]any, error) {
	path := fmt.Sprintf("/v1/streams/%s/verify", quote(c.streamID))
	var out map[string]any
	if err := c.postJSON(ctx, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InclusionProof returns the Merkle inclusion proof for a sequence.
func (c *Client) InclusionProof(ctx context.Context, sequence int64) (map[string]any, error) {
	path := fmt.Sprintf("/v1/streams/%s/inclusion-proof", quote(c.streamID))
	var out map[string]any
	if err := c.postJSON(ctx, path, map[string]int64{"sequence": sequence}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- internals ---

func (c *Client) getJSON(ctx context.Context, path string, into any) error {
	r, err := c.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if err := ensureOK(r); err != nil {
		return err
	}
	return json.NewDecoder(r.Body).Decode(into)
}

func (c *Client) postJSON(ctx context.Context, path string, body any, into any) error {
	r, err := c.do(ctx, http.MethodPost, path, body, true)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if err := ensureOK(r); err != nil {
		return err
	}
	return json.NewDecoder(r.Body).Decode(into)
}

func (c *Client) do(ctx context.Context, method, path string, body any, auth bool) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

func ensureOK(r *http.Response) error {
	if r.StatusCode < 400 {
		return nil
	}
	body, _ := io.ReadAll(r.Body)
	return &ClientError{Status: r.StatusCode, Body: string(body)}
}

func quote(streamID string) string {
	return strings.ReplaceAll(streamID, "/", "%2F")
}
