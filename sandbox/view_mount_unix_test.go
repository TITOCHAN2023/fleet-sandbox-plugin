//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

type countedViewSource struct {
	overlay.Source
	bytes atomic.Int64
}

func (s *countedViewSource) Close() error {
	if c, ok := s.Source.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}
func (s *countedViewSource) ReadAt(ctx context.Context, name, version string, b []byte, offset int64) (int, error) {
	n, err := s.Source.ReadAt(ctx, name, version, b, offset)
	s.bytes.Add(int64(n))
	return n, err
}

func TestMountedEncryptedViewRunsNativeProgramWithoutWriteThrough(t *testing.T) {
	if os.Getenv("FLEET_VIEW_MOUNT_TEST") != "1" {
		t.Skip("native mount integration is opt-in")
	}
	binary := os.Getenv("FLEET_VIEW_TEST_PLUGIN")
	if binary == "" {
		t.Fatal("native sandbox test binary required")
	}
	if cap := NativeProbe(); !cap.Available {
		t.Fatal(cap.Reason)
	}
	root, store, mountpoint := t.TempDir(), t.TempDir(), t.TempDir()
	input := filepath.Join(root, "input.txt")
	if err := os.WriteFile(input, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	lower, err := newLocalViewSource(root)
	if err != nil {
		t.Fatal(err)
	}
	source := &countedViewSource{Source: lower}
	c, err := vault.New(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	SetStorageCipher(c)
	defer SetStorageCipher(nil)
	var mu sync.Mutex
	phases := map[string]int{}
	pids := map[int]bool{}
	emit := func(kind, phase, summary string, details map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		if kind == "file" {
			phases[phase]++
			if pid, ok := details["pid"].(uint32); ok {
				pids[int(pid)] = true
			}
		}
	}
	view, err := mountFileViewSource(source, store, mountpoint, emit)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.Close(); err != nil {
			t.Error(err)
		}
	}()
	if source.bytes.Load() != 0 {
		t.Fatal("mount fetched source contents before program read")
	}
	// A nested FUSE source does not provide the native inode event contract.
	nested, err := newLocalViewSource(mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	_, nestedErr := nested.Snapshot(context.Background())
	nested.Close()
	if nestedErr == nil {
		t.Fatal("stacked mount accepted as a local version-guarded source")
	}
	script := "cat input.txt; printf changed > input.txt; mkdir dir; chmod 700 dir; printf A > dir/out; printf B >> dir/out; mv dir/out moved.txt; rm input.txt; test ! -e input.txt; cat moved.txt"
	spec := Spec{Command: "/bin/sh", Args: []string{"-c", script}, Workspace: mountpoint, CWD: mountpoint}
	b, _ := json.Marshal(spec)
	cmd := exec.Command(binary, "--native-child")
	cmd.Stdin = bytes.NewReader(b)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	code, out, errOut, err := managedRun(ctx, cmd, spec, emit)
	if err != nil || code != 0 || out != "originalAB" {
		t.Fatalf("native view failed: code=%d output=%q stderr=%q err=%v", code, out, errOut, err)
	}
	b, err = os.ReadFile(input)
	if err != nil || string(b) != "original" {
		t.Fatal("native write-through reached source")
	}
	b, err = os.ReadFile(filepath.Join(mountpoint, "moved.txt"))
	if err != nil || string(b) != "AB" {
		t.Fatal("native rename/append lost output")
	}
	files, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".obj" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(store, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("original")) || bytes.Contains(data, []byte("changed")) {
			t.Fatal("native view persisted plaintext")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, phase := range []string{"opened", "read", "written", "created", "renamed", "deleted"} {
		if phases[phase] == 0 {
			t.Fatal("native file observation missing: " + phase)
		}
	}
	if len(pids) < 1 {
		t.Fatal("file observations lack native caller PIDs")
	}
}
