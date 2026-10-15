package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Streams belong to the broker. They are inherited standard handles, never
// network capabilities or a way to read the broker's persistent store.
type Streams struct {
	Stdin  *os.File
	Stdout io.Writer
	Stderr io.Writer
}

func NativeRunStreams(ctx context.Context, spec Spec, emit Emit, streams Streams) (int, string, string, error) {
	if emit == nil {
		emit = func(string, string, string, map[string]any) {}
	}
	return nativeRun(ctx, spec, emit, &streams)
}

// RunStreams uses the same workspace, isolation, checkpoint and result paths as
// run. Ready reports the private cwd before any task program starts.
func RunStreams(ctx context.Context, cfg Config, in RunInput, streams Streams, ready func(id, cwd string) error, emit Emit) (any, error) {
	root, err := filepath.EvalSymlinks(cfg.Root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() {
		return nil, errors.New("absolute input directory required")
	}
	dir, err := dataDir()
	if err != nil {
		return nil, err
	}
	if contains(root, dir) || contains(dir, root) {
		return nil, errors.New("input root and plugin storage cannot overlap")
	}
	cfg.Root = root
	if emit == nil {
		emit = func(string, string, string, map[string]any) {}
	}
	return runConfigured(ctx, cfg, in, emit, ready, func(ctx context.Context, spec Spec, emit Emit) (int, string, string, error) {
		return NativeRunStreams(ctx, spec, emit, streams)
	})
}
