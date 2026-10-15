//go:build linux

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyscallTraceDistinguishesPolicyDenialAndOrdinaryFailure(t *testing.T) {
	events := []struct{ kind, phase string }{}
	emit := func(kind, phase, summary string, details map[string]any) {
		events = append(events, struct{ kind, phase string }{kind, phase})
	}
	emitTraceLine(`41 123.000 openat(AT_FDCWD, "/outside", O_RDONLY) = -1 EACCES (Permission denied)`, emit)
	emitTraceLine(`41 123.000 openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)`, emit)
	emitTraceLine(`42 123.001 socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)`, emit)
	if len(events) != 3 || events[0].phase != "denied" || events[1].phase != "failed" || events[2].kind != "network" {
		t.Fatalf("events: %#v", events)
	}
}
func TestLiveTracePublishesCompleteLinesBeforeExitAndReportsPartialTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := make(chan string, 4)
	done := make(chan error, 1)
	go func() {
		done <- streamSyscallTrace(ctx, path, func(kind, phase, summary string, details map[string]any) { received <- kind + ":" + phase })
	}()
	if _, err = f.WriteString(`41 123.000 openat(AT_FDCWD, "/input", O_RDONLY)`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
		t.Fatal("partial trace was emitted")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err = f.WriteString(" = 3\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-received:
		if event != "file:observed" {
			t.Fatal(event)
		}
	case <-time.After(time.Second):
		t.Fatal("live event did not arrive")
	}
	if _, err = f.WriteString("partial"); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("trace did not stop")
	}
	select {
	case event := <-received:
		if event != "coverage:gap" {
			t.Fatal(event)
		}
	default:
		t.Fatal("partial tail gap hidden")
	}
}
