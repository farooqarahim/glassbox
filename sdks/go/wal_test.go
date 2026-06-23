package glassbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWalRetainsRecordsOnRejection(t *testing.T) {
	s := startServer(t)
	defer s.stop()

	tmp := t.TempDir()
	bodyPath := filepath.Join(tmp, "body.json")
	body, _ := json.Marshal(map[string]any{
		"model": map[string]any{
			"provider":      "anthropic",
			"model_name":    "claude-opus-4-7",
			"model_version": "v",
		},
		"tags": []map[string]any{{"key": "decision_id", "value": "wal-go"}},
	})
	if err := os.WriteFile(bodyPath, body, 0o644); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if out, err := exec.Command(s.glassboxBin,
		"append",
		"--ledger", s.ledger,
		"--stream", s.streamID,
		"--key", s.key,
		"--body", bodyPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("append failed: %v: %s", err, out)
	}

	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	signed, err := c.Last(context.Background())
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if signed == nil {
		t.Fatalf("expected last record")
	}

	walPath := filepath.Join(tmp, "wal.jsonl")
	wal, err := OpenWal(c, WalOptions{Path: walPath, FlushInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("OpenWal: %v", err)
	}
	if err := wal.Enqueue(signed); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Wait long enough for the flusher to attempt + bounce off the server.
	time.Sleep(1 * time.Second)
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	lines := 0
	for _, l := range strings.Split(string(got), "\n") {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("WAL must retain the rejected record; have %d lines: %q", lines, got)
	}
}

func TestWalEmptyFlush(t *testing.T) {
	s := startServer(t)
	defer s.stop()
	tmp := t.TempDir()
	c := NewClient(Options{BaseURL: s.baseURL, Token: s.secret, StreamID: s.streamID})
	wal, err := OpenWal(c, WalOptions{Path: filepath.Join(tmp, "wal.jsonl"), FlushInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("OpenWal: %v", err)
	}
	defer wal.Close()
	if err := wal.Flush(context.Background(), time.Second); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if wal.Pending() != 0 {
		t.Fatalf("expected pending=0, got %d", wal.Pending())
	}
}
