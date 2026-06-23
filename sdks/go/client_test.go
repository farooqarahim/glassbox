package glassbox

import (
	"context"
	"errors"
	"testing"
)

func TestHealthz(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	ok, err := c.Healthz(context.Background())
	if err != nil {
		t.Fatalf("Healthz: %v", err)
	}
	if !ok {
		t.Fatalf("expected healthz=true")
	}
}

func TestListStreams(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	streams, err := c.ListStreams(context.Background())
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(streams) != 1 || streams[0] != "acme/credit" {
		t.Fatalf("unexpected streams: %v", streams)
	}
}

func TestIterRecordsReturnsGenesis(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	rs, err := c.IterRecords(context.Background())
	if err != nil {
		t.Fatalf("IterRecords: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rs))
	}
	rec, _ := rs[0]["record"].(map[string]any)
	if seq, _ := rec["sequence"].(float64); seq != 0 {
		t.Fatalf("expected sequence=0, got %v", rec["sequence"])
	}
}

func TestInclusionProofForGenesis(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	proof, err := c.InclusionProof(context.Background(), 0)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if leaf, _ := proof["leaf_hex"].(string); len(leaf) != 64 {
		t.Fatalf("leaf_hex wrong length: %v", proof["leaf_hex"])
	}
	if root, _ := proof["root_hex"].(string); len(root) != 64 {
		t.Fatalf("root_hex wrong length: %v", proof["root_hex"])
	}
}

func TestVerifyOK(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	r, err := c.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok, _ := r["ok"].(bool); !ok {
		t.Fatalf("verify reported not-ok: %v", r)
	}
	if walked, _ := r["records_walked"].(float64); walked != 1 {
		t.Fatalf("expected records_walked=1, got %v", r["records_walked"])
	}
}

func TestWrongTokenRejected(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: "wrong-secret", StreamID: s.streamID})
	_, err := c.ListStreams(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	var ce *ClientError
	if !errors.As(err, &ce) {
		t.Fatalf("expected ClientError, got %T", err)
	}
	if ce.Status != 401 && ce.Status != 403 {
		t.Fatalf("expected 401/403, got %d", ce.Status)
	}
}

func TestGetMissing(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	got, err := c.Get(context.Background(), 9999)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing sequence, got %v", got)
	}
}
