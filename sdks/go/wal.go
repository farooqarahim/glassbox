package glassbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WalBuffer is a local disk-backed write-ahead log for Glassbox
// records (spec §16.3). Records are appended + fsynced to a JSON-Lines
// file before Enqueue returns. A background goroutine drains the file
// to the configured Client; server errors leave records on disk for
// the next pass.
type WalBuffer struct {
	client        *Client
	path          string
	flushInterval time.Duration
	maxPending    int
	mu            sync.Mutex
	pendingCount  int32
	stop          chan struct{}
	done          chan struct{}
	closed        atomic.Bool
}

// WalOptions configures a WalBuffer.
type WalOptions struct {
	Path          string
	FlushInterval time.Duration
	MaxPending    int
}

// OpenWal creates (or resumes) a WAL file at opts.Path and starts the
// background drain. Returns once the parent directory exists and the
// initial pending count is known.
func OpenWal(client *Client, opts WalOptions) (*WalBuffer, error) {
	interval := opts.FlushInterval
	if interval == 0 {
		interval = time.Second
	}
	maxPending := opts.MaxPending
	if maxPending == 0 {
		maxPending = 10_000
	}

	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o755); err != nil {
		return nil, err
	}
	// Touch the file so first-read paths succeed.
	if f, err := os.OpenFile(opts.Path, os.O_CREATE|os.O_RDONLY, 0o644); err != nil {
		return nil, err
	} else {
		_ = f.Close()
	}

	w := &WalBuffer{
		client:        client,
		path:          opts.Path,
		flushInterval: interval,
		maxPending:    maxPending,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	pending, err := w.countPending()
	if err != nil {
		return nil, err
	}
	atomic.StoreInt32(&w.pendingCount, int32(pending))

	go w.loop()
	return w, nil
}

// Enqueue appends a signed record to the WAL. Returns once the bytes
// are fsynced.
func (w *WalBuffer) Enqueue(signedRecord map[string]any) error {
	if w.closed.Load() {
		return errors.New("wal: closed")
	}
	if int(atomic.LoadInt32(&w.pendingCount)) >= w.maxPending {
		return fmt.Errorf("wal: pending cap reached (%d)", w.maxPending)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	line, err := json.Marshal(map[string]any{"record": signedRecord})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	atomic.AddInt32(&w.pendingCount, 1)
	return nil
}

// Flush blocks until the WAL is empty or timeout elapses.
func (w *WalBuffer) Flush(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		w.drainOnce()
		if atomic.LoadInt32(&w.pendingCount) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wal: still holds %d records", atomic.LoadInt32(&w.pendingCount))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Close stops the background drain. Pending records remain on disk
// and will be re-shipped on the next OpenWal against the same path.
func (w *WalBuffer) Close() error {
	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(w.stop)
	<-w.done
	return nil
}

// Pending returns the current number of un-shipped records.
func (w *WalBuffer) Pending() int {
	return int(atomic.LoadInt32(&w.pendingCount))
}

func (w *WalBuffer) loop() {
	defer close(w.done)
	t := time.NewTicker(w.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.drainOnce()
		}
	}
}

func (w *WalBuffer) drainOnce() {
	w.mu.Lock()
	lines, err := w.readLines()
	w.mu.Unlock()
	if err != nil || len(lines) == 0 {
		return
	}
	remaining := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry struct {
			Record map[string]any `json:"record"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Poison record — drop to avoid an infinite retry loop.
			continue
		}
		if entry.Record == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := w.client.Append(ctx, entry.Record)
		cancel()
		if err != nil {
			remaining = append(remaining, line)
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var nextContent string
	if len(remaining) == 0 {
		nextContent = ""
	} else {
		nextContent = strings.Join(remaining, "\n") + "\n"
	}
	if err := os.WriteFile(w.path, []byte(nextContent), 0o644); err == nil {
		atomic.StoreInt32(&w.pendingCount, int32(len(remaining)))
	}
}

func (w *WalBuffer) readLines() ([]string, error) {
	f, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<26)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (w *WalBuffer) countPending() (int, error) {
	lines, err := w.readLines()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			count++
		}
	}
	return count, nil
}
