package supervisor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLeaderExitCleansUpProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "worker.pid")
	child, err := start(os.Environ(), []string{
		"/bin/sh", "-c", `sleep 120 & printf '%s\n' "$!" > "$1"; exit 7`, "test-leader", pidFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(child.stop)
	select {
	case <-child.done:
	case <-time.After(3 * time.Second):
		t.Fatal("leader did not exit")
	}
	if got := child.exitCode(); got != 7 {
		t.Fatalf("leader status: got %d, want 7", got)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 2 {
		t.Fatalf("invalid worker PID: %s", data)
	}

	// An orphan may briefly be a zombie until the namespace's init reaps it.
	stat := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		data, err := os.ReadFile(stat)
		if errors.Is(err, os.ErrNotExist) || (err == nil && bytes.Contains(data, []byte(") Z "))) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("orphaned worker remained alive after its leader exited")
}
