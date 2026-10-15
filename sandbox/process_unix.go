//go:build linux || darwin

package sandbox

import (
	"context"
	"io"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

func managedRun(ctx context.Context, cmd *exec.Cmd, spec Spec, emit Emit) (int, string, string, error) {
	return managedRunWithIO(ctx, cmd, spec, emit, nil)
}

func managedRunWithIO(ctx context.Context, cmd *exec.Cmd, spec Spec, emit Emit, streams *Streams) (int, string, string, error) {
	// Linux Pdeathsig follows the spawning OS thread. Keep it alive until
	// the launcher exits, even while this goroutine waits on I/O.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	out, errOut := &cappedOutput{}, &cappedOutput{}
	cmd.Stdout = out
	cmd.Stderr = errOut
	if streams != nil {
		cmd.Stdin = nil
		if streams.Stdin != nil {
			cmd.Stdin = streams.Stdin
		}
		if streams.Stdout != nil {
			cmd.Stdout = io.MultiWriter(out, streams.Stdout)
		}
		if streams.Stderr != nil {
			cmd.Stderr = io.MultiWriter(errOut, streams.Stderr)
		}
	}
	cmd.Env = commandEnvironment(spec.Workspace)
	cmd.Dir = spec.CWD
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return -1, "", "", err
	}
	emit("process", "started", spec.Command, map[string]any{"pid": cmd.Process.Pid, "pid_scope": "broker", "backend": "native", "observation": "launcher"})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		err = <-done
		err = ctx.Err()
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
	code := cmd.ProcessState.ExitCode()
	emit("process", "exited", spec.Command, map[string]any{"pid": cmd.Process.Pid, "pid_scope": "broker", "exit_code": code})
	if ctx.Err() != nil {
		return code, out.b.String(), errOut.b.String(), ctx.Err()
	}
	if _, ok := err.(*exec.ExitError); ok && code >= 0 {
		err = nil
	}
	return code, out.b.String(), errOut.b.String(), err
}
