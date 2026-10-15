package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
)

func workspaceView(ctx context.Context, dir string, state Workspace) (string, func(), []string, error) {
	if state.ViewMode != "demand" {
		view, cleanup, err := materializeView(dir)
		return view, cleanup, nil, err
	}
	v, err := overlay.OpenOffline(ctx, filepath.Join(dir, "file-store"), storageCipher.Load())
	if err != nil {
		return "", nil, nil, err
	}
	defer v.Close()
	temp, err := os.MkdirTemp(dir, ".materialized-")
	if err != nil {
		return "", nil, nil, err
	}
	cleanup := func() { os.RemoveAll(temp) }
	view := filepath.Join(temp, "files")
	gaps, err := v.Materialize(ctx, view)
	if err != nil {
		cleanup()
		return "", nil, gaps, err
	}
	return view, cleanup, gaps, nil
}
func changesFromHashes(after, before map[string]string, initial []overlay.Entry, gaps []string) []Change {
	baseline := make(map[string]string, len(before)+len(initial))
	for path, hash := range before {
		baseline[path] = hash
	}
	for _, entry := range initial {
		if entry.Mode.IsRegular() {
			if _, ok := baseline[entry.Path]; !ok {
				baseline[entry.Path] = ""
			}
		}
	}
	missing := map[string]bool{}
	for _, gap := range gaps {
		if !strings.HasPrefix(gap, "source:") {
			missing[gap] = true
		}
	}
	out := []Change{}
	for path, hash := range after {
		old, exists := baseline[path]
		if exists && old == hash {
			continue
		}
		operation := "modified"
		if !exists {
			operation = "created"
		}
		if exists && old == "" {
			operation = "unverified"
		}
		out = append(out, Change{Path: path, Operation: operation, Before: old, After: hash})
	}
	for path, hash := range baseline {
		if _, exists := after[path]; !exists && !missing[path] {
			out = append(out, Change{Path: path, Operation: "deleted", Before: hash})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func workspaceChanges(root string, before map[string]string, initial []overlay.Entry, gaps []string) ([]Change, error) {
	baseline := make(map[string]string, len(before)+len(initial))
	for path, hash := range before {
		baseline[path] = hash
	}
	for _, entry := range initial {
		if entry.Mode.IsRegular() {
			if _, ok := baseline[entry.Path]; !ok {
				baseline[entry.Path] = ""
			}
		}
	}
	delta, err := changes(root, baseline)
	if err != nil {
		return nil, err
	}
	missing := map[string]bool{}
	for _, gap := range gaps {
		if !strings.HasPrefix(gap, "source:") {
			missing[gap] = true
		}
	}
	out := delta[:0]
	for _, change := range delta {
		if !missing[change.Path] {
			if change.Operation == "modified" && baseline[change.Path] == "" {
				change.Operation = "unverified"
			}
			out = append(out, change)
		}
	}
	return out, nil
}
