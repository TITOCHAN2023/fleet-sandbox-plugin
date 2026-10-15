//go:build linux || darwin

package sandbox

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativeRunKeepsCallerTreeAndRefusesOutsideFileAndNetwork(t *testing.T) {
	probe := NativeProbe()
	if !probe.Available || !probe.FilesystemIsolation || !probe.NetworkDenied {
		t.Fatalf("native backend does not claim file and network denial: %+v", probe)
	}
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		tcp := listener.(*net.TCPListener)
		_ = tcp.SetDeadline(time.Now().Add(20 * time.Second))
		conn, acceptErr := tcp.Accept()
		if acceptErr == nil {
			conn.Close()
			accepted <- struct{}{}
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	local := Invocation{Origin: "local"}
	configured, _ := json.Marshal(Config{Root: root})
	if _, err = Handle(context.Background(), Request{Action: "configure", Input: configured, Context: local}, nil); err != nil {
		t.Fatal(err)
	}
	script := `printf changed > note.txt || exit 40
if printf leaked > "$1"; then echo OUTSIDE_WRITE; exit 30; fi
echo OUTSIDE_DENIED
nc -n -z -w 2 127.0.0.1 "$2"
rc=$?
if [ "$rc" -eq 0 ]; then echo NET_OPEN; exit 31; fi
if [ "$rc" -eq 127 ]; then echo rc=127; exit 127; fi
echo NET_DENIED
`
	runInput, _ := json.Marshal(RunInput{
		Command: "/bin/sh",
		Args:    []string{"-c", script, "sh", outside, strconv.Itoa(port)},
		Timeout: 30,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	raw, err := Handle(ctx, Request{Action: "run", Input: runInput, Context: local}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := raw.(Result)
	if !ok {
		t.Fatalf("result type %T", raw)
	}
	caller, err := os.ReadFile(filepath.Join(root, "input.txt"))
	if err != nil || string(caller) != "original" {
		t.Fatalf("caller tree changed: %q %v", caller, err)
	}
	if _, err = os.Stat(filepath.Join(root, "note.txt")); !os.IsNotExist(err) {
		t.Fatal("private write leaked into the caller tree")
	}
	leaked, err := os.ReadFile(outside)
	if err != nil || string(leaked) != "untouched" {
		t.Fatalf("outside file changed: %q %v", leaked, err)
	}
	select {
	case <-accepted:
		t.Fatal("sandboxed process reached the host listener")
	default:
	}
	if strings.Contains(result.Stdout, "OUTSIDE_WRITE") || strings.Contains(result.Stdout, "NET_OPEN") || strings.Contains(result.Stdout, "rc=127") {
		t.Fatalf("sandbox reported a successful escape: stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "OUTSIDE_DENIED") || !strings.Contains(result.Stdout, "NET_DENIED") {
		t.Fatalf("denied attempts were not observed: code=%d stdout=%q stderr=%q", result.ExitCode, result.Stdout, result.Stderr)
	}
	created := false
	for _, change := range result.Changes {
		if change.Path == "note.txt" && change.Operation == "created" {
			created = true
		}
	}
	if !created {
		t.Fatalf("private workspace diff missing: %+v", result.Changes)
	}
	destination := filepath.Join(t.TempDir(), "export")
	exportedRaw, _ := json.Marshal(ExportInput{ID: result.ID, Destination: destination})
	if _, err = Handle(context.Background(), Request{Action: "export", Input: exportedRaw, Context: local}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "files", "note.txt"))
	if err != nil || string(got) != "changed" {
		t.Fatalf("export: %q %v", got, err)
	}
	caller, err = os.ReadFile(filepath.Join(root, "input.txt"))
	if err != nil || string(caller) != "original" {
		t.Fatalf("export wrote the caller tree: %q %v", caller, err)
	}
	discardRaw, _ := json.Marshal(map[string]string{"sandbox_id": result.ID})
	if _, err = Handle(context.Background(), Request{Action: "discard", Input: discardRaw, Context: local}, nil); err != nil {
		t.Fatal(err)
	}
	dir, err := workspaceDir(result.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("discard left the workspace: %v", err)
	}
	caller, err = os.ReadFile(filepath.Join(root, "input.txt"))
	if err != nil || string(caller) != "original" {
		t.Fatalf("discard changed the caller tree: %q %v", caller, err)
	}
}
