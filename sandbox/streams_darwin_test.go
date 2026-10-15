//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failedStreamWriter struct{ err error }

func (w failedStreamWriter) Write([]byte) (int, error) { return 0, w.err }

func TestNativeStreamsNilInputIsEOFAndWriterFailureIsReported(t *testing.T) {
	if !NativeProbe().Available {
		t.Skip("native launcher unavailable")
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec := Spec{Command: "/bin/sh", Args: []string{"-c", "if read value; then exit 90; else printf no-input; fi"}, Workspace: root, CWD: root}
	code, out, _, err := NativeRunStreams(ctx, spec, nil, Streams{})
	if err != nil || code != 0 || out != "no-input" {
		t.Fatalf("empty standard input: %d %q %v", code, out, err)
	}
	broken := errors.New("fixture transport failed")
	spec.Args = []string{"-c", "printf response"}
	_, _, _, err = NativeRunStreams(ctx, spec, nil, Streams{Stdout: failedStreamWriter{broken}})
	if !errors.Is(err, broken) {
		t.Fatalf("stream failure acknowledged as success: %v", err)
	}
}
