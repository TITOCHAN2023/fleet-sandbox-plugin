//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var traceLine = regexp.MustCompile(`^([0-9]+)\s+([0-9.]+)\s+([a-zA-Z0-9_]+)\((.*)`)
var quotedTracePath = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// The trace file belongs to the broker and is outside the child's writable
// view. Program stderr is never parsed as an authoritative syscall event.
func emitTraceLine(line string, emit Emit) {
	matches := traceLine.FindStringSubmatch(line)
	if matches == nil {
		return
	}
	pid, _ := strconv.Atoi(matches[1])
	call, args := matches[3], matches[4]
	kind := ""
	switch call {
	case "execve", "execveat", "clone", "clone3", "fork", "vfork", "exit", "exit_group":
		kind = "process"
	case "open", "openat", "openat2", "creat", "rename", "renameat", "renameat2", "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir":
		kind = "file"
	case "socket", "connect", "bind", "sendto", "sendmsg":
		kind = "network"
	}
	if kind == "" {
		return
	}
	phase := "observed"
	if strings.Contains(args, "= -1 ") {
		phase = "failed"
		if strings.Contains(args, " EPERM ") || strings.Contains(args, " EACCES ") {
			phase = "denied"
		}
	}
	details := map[string]any{"pid": pid, "syscall": call, "observation": "syscall_trace", "timestamp": matches[2], "result": args}
	summary := call
	if quoted := quotedTracePath.FindString(args); quoted != "" {
		if path, err := strconv.Unquote(quoted); err == nil {
			summary += " " + path
			details["path"] = path
		}
	}
	emit(kind, phase, summary, details)
}

const traceMaxBytes = int64(32 << 20)

// Tail the broker-owned trace while the command runs. Partial lines remain
// buffered until their result arrives; stderr is never treated as evidence.
func streamSyscallTrace(ctx context.Context, path string, emit Emit) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReaderSize(f, 64<<10)
	pending := ""
	var consumed int64
	for {
		line, readErr := reader.ReadString('\n')
		consumed += int64(len(line))
		if consumed > traceMaxBytes {
			return errors.New("syscall trace exceeded 32 MiB")
		}
		pending += line
		if len(pending) > 64<<10 {
			return errors.New("syscall trace line exceeded 64 KiB")
		}
		if len(pending) > 0 && pending[len(pending)-1] == '\n' {
			emitTraceLine(strings.TrimSuffix(pending, "\n"), emit)
			pending = ""
		}
		if readErr == nil {
			continue
		}
		if readErr != io.EOF {
			return readErr
		}
		if ctx.Err() != nil {
			if pending != "" {
				emit("coverage", "gap", "Incomplete syscall trace tail", nil)
			}
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(25 * time.Millisecond):
		}
	}
}
