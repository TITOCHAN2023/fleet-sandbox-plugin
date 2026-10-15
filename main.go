package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--native-probe" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "manifest" {
		manifest()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--native-child-fd" {
		f := os.NewFile(3, "native-specification")
		var spec sandbox.Spec
		err := json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&spec)
		_ = f.Close()
		if err != nil {
			os.Exit(126)
		}
		if err = sandbox.NativeChild(spec); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(126)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--native-child" {
		var spec sandbox.Spec
		if json.NewDecoder(io.LimitReader(os.Stdin, 64<<10)).Decode(&spec) != nil {
			os.Exit(126)
		}
		if err := sandbox.NativeChild(spec); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(126)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) == 2 && os.Args[1] == "--stdio-workspace" {
		runFileWorkspaceStdio(ctx)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--stdio-run" {
		runStdio(ctx)
		return
	}
	var req sandbox.Request
	d := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	if err := d.Decode(&req); err != nil {
		reply(nil, err)
		return
	}
	if req.Action != "ui" {
		if err := sandbox.InitStorage(ctx); err != nil {
			reply(nil, err)
			return
		}
	}
	emit, auditStatus := sandbox.ActivityEmitter()
	result, err := sandbox.Handle(ctx, req, emit)
	if auditErr := auditStatus(); auditErr != nil && err == nil {
		err = auditErr
	}
	reply(result, err)
}
func reply(result any, err error) {
	out := map[string]any{"ok": err == nil}
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["result"] = result
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
func manifest() {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		panic(err)
	}
	entry := filepath.Base(exe)
	actions := []string{"ui", "probe", "config", "configure", "run", "inspect", "diff", "list", "export", "encrypt_storage", "discard"}
	out := map[string]any{"schema_version": 1, "id": "fleet.sandbox", "name": "Fleet Sandbox", "version": "0.1.0", "publisher": "Fleet Official", "license": "MIT", "repository": "https://github.com/TITOCHAN2023/fleet-sandbox-plugin", "runtime": "task", "actions": actions, "approval_actions": []string{}, "ui": map[string]any{"title": "Fleet Sandbox", "page_action": "ui", "read_actions": []string{"probe", "config", "inspect", "diff", "list"}, "write_actions": []string{"configure", "run", "export", "encrypt_storage", "discard"}}, "artifacts": []map[string]string{{"os": runtime.GOOS, "arch": runtime.GOARCH, "entrypoint": entry, "sha256": hex.EncodeToString(h.Sum(nil)), "url": "https://github.com/TITOCHAN2023/fleet-sandbox-plugin/releases/download/v0.1.0/" + entry}}}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
