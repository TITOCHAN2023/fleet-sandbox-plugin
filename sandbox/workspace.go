package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/filelock"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Workspace metadata lives outside the native process's writable view.
type Workspace struct {
	ViewMode     string            `json:"view_mode,omitempty"`
	Initial      []overlay.Entry   `json:"initial,omitempty"`
	RecoveryGaps []string          `json:"recovery_gaps,omitempty"`
	Encrypted    bool              `json:"encrypted_persistence"`
	ID           string            `json:"sandbox_id"`
	State        string            `json:"state"`
	Created      int64             `json:"created"`
	InputRoot    string            `json:"input_root"`
	Before       map[string]string `json:"before,omitempty"`
}

func saveWorkspace(dir string, state Workspace) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeState(filepath.Join(dir, "workspace.json"), b)
}
func loadWorkspace(dir string) (Workspace, error) {
	var state Workspace
	b, err := readState(filepath.Join(dir, "workspace.json"))
	if err == nil {
		err = json.Unmarshal(b, &state)
	}
	return state, err
}
func lockedWorkspace(id string) (string, func(), error) {
	dir, err := workspaceDir(id)
	if err != nil {
		return "", nil, err
	}
	storage, err := dataDir()
	if err != nil {
		return "", nil, err
	}
	locks := filepath.Join(storage, "locks")
	if err = os.MkdirAll(locks, 0700); err != nil {
		return "", nil, err
	}
	release, err := filelock.Acquire(filepath.Join(locks, id+".lock"))
	return dir, release, err
}

// A stale running marker becomes interrupted only after obtaining its OS lock.
// A different plugin process may still own a live invocation.
func recoverWorkspace(dir string) (Workspace, error) {
	state, err := loadWorkspace(dir)
	if err != nil {
		return state, err
	}
	if state.State == "running" || state.State == "preparing" {
		var result Result
		if b, readErr := readState(filepath.Join(dir, "result.json")); readErr == nil && json.Unmarshal(b, &result) == nil && result.ID == state.ID {
			state.State = result.State
			return state, saveWorkspace(dir, state)
		}
		state.State = "interrupted"
		err = saveWorkspace(dir, state)
	}
	return state, err
}
func inspectWorkspace(id string) (Result, error) {
	dir, release, err := lockedWorkspace(id)
	if err != nil {
		return Result{}, err
	}
	defer release()
	state, stateErr := recoverWorkspace(dir)
	b, err := readState(filepath.Join(dir, "result.json"))
	if err == nil {
		var result Result
		err = json.Unmarshal(b, &result)
		return result, err
	}
	if stateErr != nil {
		return Result{}, stateErr
	}
	if !os.IsNotExist(err) {
		return Result{}, err
	}
	result := Result{ID: id, State: state.State, ExitCode: -1}
	view, cleanup, gaps, err := workspaceView(context.Background(), dir, state)
	if err != nil {
		return result, err
	}
	defer cleanup()
	result.ViewMode = state.ViewMode
	result.RecoveryGaps = gaps
	result.Changes, err = workspaceChanges(view, state.Before, state.Initial, gaps)
	return result, err
}
func listWorkspaces() ([]Workspace, error) {
	storage, err := dataDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(storage, "workspaces"))
	if os.IsNotExist(err) {
		return []Workspace{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Workspace{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir, release, lockErr := lockedWorkspace(entry.Name())
		if lockErr != nil {
			if dir == "" {
				continue
			}
			state, readErr := loadWorkspace(dir)
			if readErr == nil {
				state.Before = nil
				state.Initial = nil
				out = append(out, state)
			}
			continue
		}
		state, readErr := recoverWorkspace(dir)
		release()
		if readErr != nil {
			continue
		}
		state.Before = nil
		state.Initial = nil
		out = append(out, state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

type ExportInput struct {
	ID          string `json:"sandbox_id"`
	Destination string `json:"destination"`
}
type ExportResult struct {
	ID               string   `json:"sandbox_id"`
	Destination      string   `json:"destination"`
	Conflicts        []Change `json:"input_changes_since_snapshot"`
	InputUnavailable bool     `json:"input_unavailable"`
	RecoveryGaps     []string `json:"recovery_gaps,omitempty"`
	Incomplete       bool     `json:"incomplete"`
}

// Export publishes a new directory, with result files and a deletion manifest.
// It never overwrites an existing path or applies deletions to the input root.
func exportWorkspace(ctx context.Context, input ExportInput, emit Emit) (ExportResult, error) {
	out := ExportResult{ID: input.ID}
	if !filepath.IsAbs(input.Destination) {
		return out, errors.New("export destination must be absolute")
	}
	dir, release, err := lockedWorkspace(input.ID)
	if err != nil {
		return out, err
	}
	defer release()
	state, err := recoverWorkspace(dir)
	if err != nil {
		return out, err
	}
	if !filepath.IsAbs(state.InputRoot) || state.Before == nil && state.ViewMode != "demand" {
		return out, errors.New("workspace has no trusted snapshot metadata")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(input.Destination)))
	if err != nil {
		return out, err
	}
	destination := filepath.Join(parent, filepath.Base(filepath.Clean(input.Destination)))
	storage, err := dataDir()
	if err != nil {
		return out, err
	}
	if contains(storage, destination) {
		return out, errors.New("export must be outside plugin storage")
	}
	if _, err = os.Lstat(destination); !os.IsNotExist(err) {
		return out, errors.New("export destination already exists or cannot be inspected")
	}
	view, cleanup, gaps, err := workspaceView(ctx, dir, state)
	if err != nil {
		return out, err
	}
	defer cleanup()
	out.RecoveryGaps = gaps
	out.Incomplete = len(gaps) > 0
	delta, err := workspaceChanges(view, state.Before, state.Initial, gaps)
	if err != nil {
		return out, err
	}
	// Report concurrent changes to the input. They do not alter the private view.
	out.Conflicts, err = workspaceChanges(state.InputRoot, state.Before, state.Initial, nil)
	if err != nil {
		out.InputUnavailable = true
		out.Conflicts = nil
	}
	for _, entry := range state.Initial {
		if entry.Mode.IsRegular() && state.Before[entry.Path] == "" {
			out.InputUnavailable = true
			break
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	tmp, err := os.MkdirTemp(parent, ".fleet-export-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(tmp)
	files := filepath.Join(tmp, "files")
	if err = os.Mkdir(files, 0700); err != nil {
		return out, err
	}
	if _, err = snapshot(view, files); err != nil {
		return out, err
	}
	manifest := map[string]any{"schema_version": 1, "sandbox_id": input.ID, "state": state.State, "view_mode": state.ViewMode, "changes": delta, "input_changes_since_snapshot": out.Conflicts, "input_unavailable": out.InputUnavailable, "recovery_gaps": gaps, "incomplete": out.Incomplete, "exported_at": time.Now().UnixMilli()}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return out, err
	}
	if err = atomicWrite(filepath.Join(tmp, "manifest.json"), b); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = publishDirectory(tmp, destination); err != nil {
		return out, fmt.Errorf("publish export without replacing existing data: %w", err)
	}
	out.Destination = destination
	emit("workspace", "exported", input.ID, map[string]any{"destination": destination, "input_conflicts": len(out.Conflicts), "input_unavailable": out.InputUnavailable})
	return out, nil
}
