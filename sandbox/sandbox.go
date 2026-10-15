// Package sandbox owns native execution and workspace semantics. Fleet Core
// knows only the generic task, UI, and activity protocols.
package sandbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Invocation struct {
	V        int    `json:"v"`
	Corr     string `json:"corr"`
	Origin   string `json:"origin"`
	DeviceID string `json:"device_id"`
}
type Request struct {
	Action  string          `json:"action"`
	Input   json.RawMessage `json:"input"`
	Context Invocation      `json:"context"`
}
type Capability struct {
	Backend                string `json:"backend"`
	Available              bool   `json:"available"`
	Reason                 string `json:"reason,omitempty"`
	FilesystemIsolation    bool   `json:"filesystem_isolation"`
	NetworkDenied          bool   `json:"network_denied"`
	ProcessTreeContainment bool   `json:"process_tree_containment"`
	RealtimeTrace          bool   `json:"realtime_trace"`
	ChildExecAudit         bool   `json:"child_exec_audit"`
	FileAccessAudit        bool   `json:"file_access_audit"`
	NetworkAttemptAudit    bool   `json:"network_attempt_audit"`
	Experimental           bool   `json:"experimental,omitempty"`
}
type Config struct {
	Root     string `json:"root"`
	ViewMode string `json:"view_mode,omitempty"`
}
type RunInput struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	CWD     string   `json:"cwd,omitempty"`
	Timeout int      `json:"timeout_seconds,omitempty"`
}
type Spec struct {
	Namespaced bool     `json:"namespaced,omitempty"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	Workspace  string   `json:"workspace"`
	CWD        string   `json:"cwd"`
}
type Result struct {
	ViewMode     string     `json:"view_mode,omitempty"`
	RecoveryGaps []string   `json:"recovery_gaps,omitempty"`
	Encrypted    bool       `json:"encrypted_persistence"`
	State        string     `json:"state"`
	OK           bool       `json:"ok"`
	ID           string     `json:"sandbox_id"`
	ExitCode     int        `json:"exit_code"`
	Stdout       string     `json:"stdout"`
	Stderr       string     `json:"stderr"`
	Coverage     Capability `json:"coverage"`
	Changes      []Change   `json:"changes"`
}
type Change struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
}
type Emit func(kind, phase, summary string, details map[string]any)

func ActivityEmitter() (Emit, func() error) {
	url, token := os.Getenv("FLEET_PLUGIN_ACTIVITY_URL"), os.Getenv("FLEET_PLUGIN_ACTIVITY_TOKEN")
	client := &http.Client{Timeout: 2 * time.Second}
	var mu sync.Mutex
	var firstError error
	failures := 0
	remember := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures++
		if firstError == nil {
			firstError = err
		}
	}
	emit := func(kind, phase, summary string, details map[string]any) {
		if url == "" && token == "" {
			return
		}
		if url == "" || token == "" {
			remember(errors.New("incomplete activity capability"))
			return
		}
		b, err := json.Marshal(map[string]any{"kind": kind, "phase": phase, "summary": summary, "details": details})
		if err != nil {
			remember(err)
			return
		}
		req, err := http.NewRequest("POST", url, strings.NewReader(string(b)))
		if err != nil {
			remember(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			remember(err)
			return
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			remember(fmt.Errorf("activity endpoint returned %d", response.StatusCode))
		}
	}
	status := func() error {
		mu.Lock()
		defer mu.Unlock()
		if firstError != nil {
			return fmt.Errorf("%d activity records could not be acknowledged: %w", failures, firstError)
		}
		return nil
	}
	return emit, status
}

func dataDir() (string, error) {
	dir := os.Getenv("FLEET_PLUGIN_DATA_DIR")
	if !filepath.IsAbs(dir) {
		return "", errors.New("FLEET_PLUGIN_DATA_DIR must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(dir)
}
func configPath() (string, error) {
	dir, err := dataDir()
	return filepath.Join(dir, "config.json"), err
}
func loadConfig() (Config, error) {
	path, err := configPath()
	if err != nil {
		return Config{}, err
	}
	b, err := readState(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}

func Handle(ctx context.Context, req Request, emit Emit) (any, error) {
	if emit == nil {
		emit = func(string, string, string, map[string]any) {}
	}
	switch req.Action {
	case "ui":
		return map[string]any{"html": Page}, nil
	case "probe":
		return NativeProbe(), nil
	case "config":
		cfg, err := loadConfig()
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return cfg, err
	case "configure":
		if req.Context.Origin != "local" {
			return nil, errors.New("policy configuration requires the local device page")
		}
		var cfg Config
		if json.Unmarshal(req.Input, &cfg) != nil {
			return nil, errors.New("invalid configuration")
		}
		root, err := filepath.EvalSymlinks(cfg.Root)
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(root) {
			return nil, errors.New("absolute root required")
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return nil, errors.New("root must be a directory")
		}
		dir, err := dataDir()
		if err != nil {
			return nil, err
		}
		if contains(root, dir) || contains(dir, root) {
			return nil, errors.New("input root and plugin storage cannot overlap")
		}
		cfg.Root = root
		cfg.ViewMode, err = viewMode(cfg.ViewMode)
		if err != nil {
			return nil, err
		}
		path, err := configPath()
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(cfg)
		if err = writeState(path, b); err != nil {
			return nil, err
		}
		emit("workspace", "configured", "Input root configured", map[string]any{"root": root})
		return cfg, nil
	case "run":
		return run(ctx, req, emit)
	case "encrypt_storage":
		return protectStoredWorkspaces(req, emit)
	case "list":
		return listWorkspaces()
	case "export":
		if req.Context.Origin != "local" {
			return nil, errors.New("export requires the local device page")
		}
		var input ExportInput
		if json.Unmarshal(req.Input, &input) != nil {
			return nil, errors.New("invalid export input")
		}
		return exportWorkspace(ctx, input, emit)
	case "diff", "inspect":
		var input struct {
			ID string `json:"sandbox_id"`
		}
		if json.Unmarshal(req.Input, &input) != nil {
			return nil, errors.New("invalid sandbox id")
		}
		return inspectWorkspace(input.ID)
	case "discard":
		if req.Context.Origin != "local" {
			return nil, errors.New("discard requires the local device page")
		}
		var input struct {
			ID string `json:"sandbox_id"`
		}
		if json.Unmarshal(req.Input, &input) != nil {
			return nil, errors.New("invalid sandbox id")
		}
		dir, release, err := lockedWorkspace(input.ID)
		if err != nil {
			return nil, err
		}
		defer release()
		if err = cleanupWorkspaceMount(dir); err != nil {
			return nil, err
		}
		if err = os.RemoveAll(dir); err != nil {
			return nil, err
		}
		emit("workspace", "discarded", input.ID, nil)
		return map[string]bool{"ok": true}, nil
	default:
		return nil, errors.New("unknown sandbox action")
	}
}

func contains(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func workspaceDir(id string) (string, error) {
	if len(id) != 32 {
		return "", errors.New("invalid sandbox id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", err
	}
	dir, err := dataDir()
	return filepath.Join(dir, "workspaces", id), err
}
func atomicWrite(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return replaceState(tmp.Name(), path)
}

func run(parent context.Context, req Request, emit Emit) (any, error) {
	var input RunInput
	if json.Unmarshal(req.Input, &input) != nil {
		return nil, errors.New("invalid run input")
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("configure the input root locally first: %w", err)
	}
	return runConfigured(parent, cfg, input, emit, nil, NativeRun)
}

func runConfigured(parent context.Context, cfg Config, input RunInput, emit Emit, ready func(id, cwd string) error, execute func(context.Context, Spec, Emit) (int, string, string, error)) (out any, returnErr error) {
	cap := NativeProbe()
	emit("coverage", "reported", cap.Backend, map[string]any{"filesystem_isolation": cap.FilesystemIsolation, "network_denied": cap.NetworkDenied, "child_exec_audit": cap.ChildExecAudit, "file_access_audit": cap.FileAccessAudit, "network_attempt_audit": cap.NetworkAttemptAudit, "process_tree_containment": cap.ProcessTreeContainment, "realtime_trace": cap.RealtimeTrace, "trace_limit_bytes": 32 << 20, "trace_string_bytes": 256})
	if !cap.Available {
		return nil, errors.New(cap.Reason)
	}
	if input.Command == "" || len(input.Args) > 256 {
		return nil, errors.New("command and valid args required")
	}
	if input.CWD != "" && !filepath.IsLocal(input.CWD) {
		return nil, errors.New("cwd must be relative to the workspace")
	}
	if input.Timeout <= 0 {
		input.Timeout = 300
	}
	if input.Timeout > 3600 {
		return nil, errors.New("timeout exceeds one hour")
	}
	var err error
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, err
	}
	mode, err := viewMode(cfg.ViewMode)
	if err != nil {
		return nil, err
	}
	result := Result{ID: hex.EncodeToString(id[:]), Coverage: cap, ViewMode: mode}
	dir, release, err := lockedWorkspace(result.ID)
	if err != nil {
		return nil, err
	}
	defer release()
	work := filepath.Join(dir, "view")
	if err = os.MkdirAll(work, 0700); err != nil {
		return nil, err
	}
	state := Workspace{ID: result.ID, State: "preparing", Created: time.Now().UnixMilli(), InputRoot: cfg.Root, ViewMode: mode}
	if err = saveWorkspace(dir, state); err != nil {
		return nil, err
	}
	finished := false
	var view *executionView
	defer func() {
		if view != nil {
			if err := view.Close(); err != nil {
				returnErr = errors.Join(returnErr, err)
				return
			}
		}
		if finished {
			return
		}
		if _, e := os.Stat(dir); os.IsNotExist(e) {
			return
		}
		state.State = "failed"
		if storageCipher.Load() != nil {
			e := sealTrace(dir)
			if mode != "demand" {
				e = errors.Join(e, sealView(dir))
			}
			state.Encrypted = e == nil
			if e != nil {
				emit("coverage", "gap", "Failed workspace could not be fully sealed", map[string]any{"error": e.Error()})
				returnErr = errors.Join(returnErr, e)
			}
		}
		returnErr = errors.Join(returnErr, saveWorkspace(dir, state))
	}()
	view, err = prepareExecutionView(parent, cfg, dir, emit)
	if err != nil {
		return nil, err
	}
	state.Before = view.before
	state.Initial = view.initial
	state.State = "running"
	if err = saveWorkspace(dir, state); err != nil {
		return nil, err
	}
	emit("workspace", "created", result.ID, map[string]any{"input_root": cfg.Root, "workspace": work})
	cwd := work
	if input.CWD != "" {
		if filepath.IsAbs(input.CWD) {
			return nil, errors.New("cwd must be relative to the workspace")
		}
		cwd, err = filepath.EvalSymlinks(filepath.Join(work, input.CWD))
		if err != nil || !contains(work, cwd) {
			return nil, errors.New("cwd escapes workspace")
		}
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(input.Timeout)*time.Second)
	defer cancel()
	if ready != nil {
		if err = ready(result.ID, cwd); err != nil {
			return nil, err
		}
	}
	result.ExitCode, result.Stdout, result.Stderr, err = execute(ctx, Spec{Command: input.Command, Args: input.Args, Workspace: work, CWD: cwd}, emit)
	result.OK = err == nil && result.ExitCode == 0
	result.State = "failed"
	if result.OK {
		result.State = "succeeded"
	}
	if ctx.Err() != nil {
		result.State = "canceled"
	}
	if err != nil {
		result.Stderr = err.Error()
		result.ExitCode = -1
	}
	checkpointCtx, stopCheckpoint := context.WithTimeout(context.Background(), 30*time.Second)
	result.RecoveryGaps, err = view.checkpoint(checkpointCtx)
	stopCheckpoint()
	state.Before = view.before
	state.RecoveryGaps = result.RecoveryGaps
	if err != nil {
		result.RecoveryGaps = append(result.RecoveryGaps, "checkpoint: "+err.Error())
		state.RecoveryGaps = result.RecoveryGaps
	}
	if err = saveWorkspace(dir, state); err != nil {
		return nil, err
	}
	if mode == "demand" {
		var hashes map[string]string
		var gaps []string
		hashCtx, stopHash := context.WithTimeout(context.Background(), 30*time.Second)
		hashes, gaps, err = view.demand.Hashes(hashCtx)
		stopHash()
		result.RecoveryGaps = append(result.RecoveryGaps, gaps...)
		state.RecoveryGaps = result.RecoveryGaps
		result.Changes = changesFromHashes(hashes, view.before, state.Initial, result.RecoveryGaps)
	} else {
		result.Changes, err = changes(work, view.before)
	}
	if err != nil {
		return nil, err
	}
	if len(result.RecoveryGaps) > 0 {
		result.OK = false
		if result.State != "canceled" {
			result.State = "failed"
		}
		emit("coverage", "gap", "Some source data could not be checkpointed", map[string]any{"paths": result.RecoveryGaps})
	}
	for _, change := range result.Changes {
		emit("file", change.Operation, change.Path, map[string]any{"before": change.Before, "after": change.After, "observation": "workspace_diff"})
	}
	if storageCipher.Load() != nil {
		if err = sealTrace(dir); err != nil {
			return nil, err
		}
		if view.demand != nil {
			if err = view.Close(); err != nil {
				return nil, err
			}
			if err = os.RemoveAll(work); err != nil {
				return nil, err
			}
		} else if err = sealView(dir); err != nil {
			return nil, err
		}
		result.Encrypted = true
	}
	if view.demand != nil {
		if err = view.Close(); err != nil {
			return nil, err
		}
		if err = os.RemoveAll(work); err != nil {
			return nil, err
		}
	}
	b, _ := json.Marshal(result)
	if err = writeState(filepath.Join(dir, "result.json"), b); err != nil {
		return nil, err
	}
	state.State = result.State
	state.Encrypted = result.Encrypted
	if err = saveWorkspace(dir, state); err != nil {
		return nil, err
	}
	finished = true
	return result, nil
}

const snapshotMax = int64(512 << 20)

func snapshot(source, destination string) (map[string]string, error) {
	root, err := filepath.EvalSymlinks(source)
	if err != nil {
		return nil, err
	}
	hashes := map[string]string{}
	var total int64
	entries := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 10000 {
			return errors.New("input exceeds 10000 entries")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not accepted in input: %s", rel)
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(destination, rel), 0700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special input file: %s", rel)
		}
		total += info.Size()
		if total > snapshotMax {
			return errors.New("input exceeds 512 MiB")
		}
		in, err := openWorkspaceFile(root, rel)
		if err != nil {
			return err
		}
		defer in.Close()
		current, err := in.Stat()
		if err != nil || !os.SameFile(info, current) {
			return errors.New("input changed during snapshot")
		}
		out, err := os.OpenFile(filepath.Join(destination, rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0700)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, info.Size()+1))
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() {
			return errors.New("input size changed")
		}
		after, err := in.Stat()
		if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			return errors.New("input changed during snapshot")
		}
		hashes[filepath.ToSlash(rel)] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return hashes, err
}

func changes(root string, before map[string]string) ([]Change, error) {
	out := []Change{}
	seen := map[string]bool{}
	var total int64
	entries := 0
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 10000 {
			return errors.New("output exceeds 10000 entries")
		}
		if e.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := e.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			out = append(out, Change{Path: rel, Operation: "special"})
			return nil
		}
		total += info.Size()
		if total > snapshotMax {
			return errors.New("output exceeds 512 MiB")
		}
		f, err := openWorkspaceFile(root, filepath.FromSlash(rel))
		if err != nil {
			return err
		}
		h := sha256.New()
		current, statErr := f.Stat()
		if statErr != nil || !os.SameFile(info, current) {
			f.Close()
			return errors.New("workspace changed during diff")
		}
		n, copyErr := io.Copy(h, io.LimitReader(f, info.Size()+1))
		afterInfo, afterErr := f.Stat()
		_ = f.Close()
		err = copyErr
		if err == nil && (n != info.Size() || afterErr != nil || afterInfo.Size() != info.Size() || !afterInfo.ModTime().Equal(info.ModTime())) {
			err = errors.New("workspace changed during diff")
		}
		if err != nil {
			return err
		}
		after := hex.EncodeToString(h.Sum(nil))
		seen[rel] = true
		if before[rel] != after {
			op := "modified"
			if _, ok := before[rel]; !ok {
				op = "created"
			}
			out = append(out, Change{rel, op, before[rel], after})
		}
		return nil
	})
	for path, hash := range before {
		if !seen[path] {
			out = append(out, Change{Path: path, Operation: "deleted", Before: hash})
		}
	}
	return out, err
}

// Task processes receive a fresh environment; neither Fleet credentials nor
// audit/page capabilities are inherited by the untrusted program.
func commandEnvironment(work string) []string {
	out := []string{}
	for _, key := range []string{"PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"} {
		if v := os.Getenv(key); v != "" {
			out = append(out, key+"="+v)
		}
	}
	home := filepath.Join(work, ".home")
	tmp := filepath.Join(work, ".tmp")
	_ = os.MkdirAll(home, 0700)
	_ = os.MkdirAll(tmp, 0700)
	return append(out, "HOME="+home, "USERPROFILE="+home, "TMPDIR="+tmp, "TMP="+tmp, "TEMP="+tmp)
}

type cappedOutput struct{ b strings.Builder }

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (128 << 10) - b.b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.b.Write(p)
	}
	return n, nil
}
