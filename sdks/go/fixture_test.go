package glassbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type serverHandle struct {
	baseURL     string
	secret      string
	streamID    string
	ledger      string
	key         string
	glassboxBin string
	proc        *exec.Cmd
}

func (s *serverHandle) stop() {
	if s.proc != nil && s.proc.Process != nil {
		_ = s.proc.Process.Kill()
		_, _ = s.proc.Process.Wait()
	}
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitFor(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("server didn't come up: %s; last=%v", url, lastErr)
}

func startServer(t *testing.T) *serverHandle {
	t.Helper()
	root := repoRoot()
	glassboxBin := filepath.Join(root, "target", "debug", "glassbox")
	serverBin := filepath.Join(root, "target", "debug", "glassbox-server")
	if _, err := os.Stat(glassboxBin); err != nil {
		t.Skipf("cargo build --workspace not run yet: %v", err)
	}
	if _, err := os.Stat(serverBin); err != nil {
		t.Skipf("glassbox-server missing: %v", err)
	}

	tmp := t.TempDir()
	key := filepath.Join(tmp, "op.key")
	ledger := filepath.Join(tmp, "ledger.db")
	tokenFile := filepath.Join(tmp, "tok.json")

	if out, err := exec.Command(glassboxBin, "keygen", "--out", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen failed: %v: %s", err, out)
	}
	if out, err := exec.Command(glassboxBin,
		"init",
		"--ledger", ledger,
		"--tenant", "acme",
		"--system", "credit",
		"--key", key,
	).CombinedOutput(); err != nil {
		t.Fatalf("init failed: %v: %s", err, out)
	}

	tok, _ := json.Marshal(map[string]any{
		"token_id": "t1",
		"scope": map[string]any{
			"tenant_id":     "acme",
			"stream_id":     "acme/credit",
			"allowed_tools": []string{},
			"expires_at":    "2099-01-01T00:00:00Z",
		},
		"secret": "sssh",
	})
	if err := os.WriteFile(tokenFile, tok, 0o644); err != nil {
		t.Fatalf("write token: %v", err)
	}

	port, err := freePort()
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	bind := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command(serverBin,
		"--ledger", ledger,
		"--key", key,
		"--token", tokenFile,
		"--bind", bind,
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	if err := waitFor("http://"+bind+"/healthz", 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("server didn't come up: %v", err)
	}
	return &serverHandle{
		baseURL:     "http://" + bind,
		secret:      "sssh",
		streamID:    "acme/credit",
		ledger:      ledger,
		key:         key,
		glassboxBin: glassboxBin,
		proc:        cmd,
	}
}

// _ keeps context import used even if some tests are skipped
var _ = context.Background
