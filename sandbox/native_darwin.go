//go:build darwin

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Seatbelt is an experimental native backend. It never falls back to an
// unrestricted process when the OS rejects a profile. A signed App Sandbox
// helper remains necessary for a supported, distributable macOS backend.
func NativeProbe() Capability {
	_, err := os.Stat("/usr/bin/sandbox-exec")
	cap := Capability{Backend: "darwin-seatbelt", Available: err == nil, FilesystemIsolation: err == nil, NetworkDenied: err == nil, Experimental: true}
	if err != nil {
		cap.Reason = "native Seatbelt launcher unavailable"
	}
	return cap
}
func NativeChild(Spec) error { return errors.New("native child entry is Linux-only") }
func NativeRun(ctx context.Context, spec Spec, emit Emit) (int, string, string, error) {
	return nativeRun(ctx, spec, emit, nil)
}
func nativeRun(ctx context.Context, spec Spec, emit Emit, streams *Streams) (int, string, string, error) {
	command, err := exec.LookPath(spec.Command)
	if err != nil {
		return -1, "", "", err
	}
	command, err = filepath.EvalSymlinks(command)
	if err != nil {
		return -1, "", "", err
	}
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	reads := []string{"/System", "/usr", "/bin", "/sbin", "/Library/Apple", spec.Workspace}
	for _, root := range []string{"/opt/homebrew", "/usr/local"} {
		if contains(root, command) {
			reads = append(reads, root)
		}
	}
	profile := "(version 1)(allow file-read-data (literal \"/\"))(deny default)(allow process-exec)(allow process-fork)(allow sysctl-read)(allow signal (target self))"
	for _, root := range reads {
		profile += "(allow file-read* (subpath " + quote(root) + "))(allow file-map-executable (subpath " + quote(root) + "))"
	}
	profile += "(allow file-map-executable (literal " + quote(command) + "))(allow file-read* (literal " + quote(command) + "))(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))"
	profile += "(allow file-write* (subpath " + quote(spec.Workspace) + ") (literal \"/dev/null\"))"
	profile += "(allow mach-lookup (global-name \"com.apple.system.logger\"))"
	if strings.ContainsRune(profile, '\x00') {
		return -1, "", "", fmt.Errorf("invalid native profile")
	}
	args := append([]string{"-p", profile, command}, spec.Args...)
	return managedRunWithIO(ctx, exec.Command("/usr/bin/sandbox-exec", args...), spec, emit, streams)
}
