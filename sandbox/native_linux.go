//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func landlockVersion() int {
	v, _, err := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, 1)
	if err != 0 {
		return 0
	}
	return int(v)
}
func nativeNamespaceAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL}
}
func nativeNamespacesAvailable() (bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--native-probe")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = nativeNamespaceAttributes()
	err = cmd.Run()
	return err == nil, err
}
func NativeProbe() Capability {
	v := landlockVersion()
	available := v >= 6
	namespaces, namespaceErr := nativeNamespacesAvailable()
	if v >= 3 && v < 6 {
		available = namespaces
	}
	cap := Capability{ProcessTreeContainment: available && namespaces, Backend: "linux-landlock-seccomp", Available: available, FilesystemIsolation: available, NetworkDenied: available}
	if available && namespaces {
		cap.Backend = "linux-namespaces-landlock-seccomp"
	}
	if _, err := exec.LookPath("strace"); err == nil && available {
		cap.RealtimeTrace = true
		cap.ChildExecAudit = true
		cap.FileAccessAudit = true
		cap.NetworkAttemptAudit = true
	}
	if !available {
		cap.Reason = fmt.Sprintf("Landlock ABI %d: requires ABI 6, or ABI 3 with permitted user/PID/network namespaces; namespaces: %v", v, namespaceErr)
	}
	return cap
}

func NativeRun(ctx context.Context, spec Spec, emit Emit) (int, string, string, error) {
	return nativeRun(ctx, spec, emit, nil)
}
func nativeRun(ctx context.Context, spec Spec, emit Emit, streams *Streams) (int, string, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return -1, "", "", err
	}
	namespaces, _ := nativeNamespacesAvailable()
	spec.Namespaced = namespaces
	if landlockVersion() < 6 && !namespaces {
		return -1, "", "", errors.New("native PID/network namespaces unavailable")
	}
	b, _ := json.Marshal(spec)
	childArgs := []string{"--native-child"}
	if streams != nil {
		if len(b) > 64<<10 {
			return -1, "", "", errors.New("native specification exceeds 64 KiB")
		}
		childArgs = []string{"--native-child-fd"}
	}
	cmd := exec.Command(exe, childArgs...)
	trace := ""
	if tracer, e := exec.LookPath("strace"); e == nil {
		trace = filepath.Join(filepath.Dir(spec.Workspace), "syscalls.log")
		f, e := os.OpenFile(trace, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return -1, "", "", e
		}
		f.Close()
		traceArgs := []string{"-f", "-qq", "-ttt", "-s", "256", "-e", "trace=process,file,network", "-o", trace, exe}
		cmd = exec.Command(tracer, append(traceArgs, childArgs...)...)
	}
	if spec.Namespaced {
		cmd.SysProcAttr = nativeNamespaceAttributes()
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	}
	cmd.Stdin = strings.NewReader(string(b))
	var specR *os.File
	var specDone chan error
	if streams != nil {
		var specW *os.File
		specR, specW, err = os.Pipe()
		if err != nil {
			return -1, "", "", err
		}
		defer specR.Close()
		cmd.ExtraFiles = []*os.File{specR}
		specDone = make(chan error, 1)
		go func() { _, e := specW.Write(b); specW.Close(); specDone <- e }()
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	traceCtx, stopTrace := context.WithCancel(context.Background())
	defer stopTrace()
	traceDone := make(chan error, 1)
	guardDone := make(chan error, 1)
	if trace != "" {
		go func() {
			traceEmit := func(kind, phase, summary string, details map[string]any) {
				if details != nil {
					details["pid_scope"] = "broker"
					if spec.Namespaced {
						details["pid_scope"] = "task_namespace"
					}
				}
				emit(kind, phase, summary, details)
			}
			err := streamSyscallTrace(traceCtx, trace, traceEmit)
			if err != nil {
				cancelRun()
			}
			traceDone <- err
		}()
		go func() {
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-traceCtx.Done():
					guardDone <- nil
					return
				case <-ticker.C:
					info, e := os.Stat(trace)
					if e != nil || info.Size() > traceMaxBytes {
						if e == nil {
							e = errors.New("syscall trace exceeded 32 MiB")
						}
						cancelRun()
						guardDone <- e
						return
					}
				}
			}
		}()
	}
	code, out, errOut, runErr := managedRunWithIO(runCtx, cmd, spec, emit, streams)
	if specR != nil {
		_ = specR.Close()
		runErr = errors.Join(runErr, <-specDone)
	}
	stopTrace()
	if trace != "" {
		traceErr, guardErr := <-traceDone, <-guardDone
		if traceErr == nil {
			traceErr = guardErr
		}
		if traceErr != nil {
			emit("coverage", "gap", "Syscall trace incomplete", map[string]any{"error": traceErr.Error()})
			runErr = traceErr
		}
	}
	return code, out, errOut, runErr

}

func NativeChild(spec Spec) error {
	runtime.LockOSThread()
	v := landlockVersion()
	if v < 3 || v < 6 && !spec.Namespaced {
		return errors.New("Landlock unavailable")
	}
	command, err := exec.LookPath(spec.Command)
	if err != nil {
		return err
	}
	if err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	handled := uint64((1 << 15) - 1)
	rule := struct {
		Handled uint64
		Network uint64
		Scoped  uint64
	}{handled, 0, 0}
	if v >= 6 {
		rule.Scoped = 3
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&rule)), unsafe.Sizeof(rule), 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))
	read := uint64(1<<0 | 1<<2 | 1<<3)
	paths := map[string]uint64{"/usr": read, "/bin": read, "/lib": read, "/lib64": read, "/etc/ld.so.cache": read, "/etc/alternatives": read, "/etc/localtime": read, "/dev/null": 1<<1 | 1<<2, "/dev/urandom": 1 << 2, spec.Workspace: handled}
	if filepath.IsAbs(command) {
		paths[command] = read
	}
	for path, access := range paths {
		parent, e := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		info, e := os.Stat(path)
		if e != nil {
			unix.Close(parent)
			return e
		}
		if !info.IsDir() {
			access &= (1<<0 | 1<<1 | 1<<2 | 1<<14)
		}
		attr := struct {
			Allowed uint64
			Parent  int32
			Pad     uint32
		}{access, int32(parent), 0}
		_, _, e2 := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, 1, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
		unix.Close(parent)
		if e2 != 0 {
			return fmt.Errorf("Landlock rule %s: %w", path, e2)
		}
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
	if errno != 0 {
		return errno
	}
	if spec.Namespaced {
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		caps := [2]unix.CapUserData{}
		if err = unix.Capset(&header, &caps[0]); err != nil {
			return err
		}
	}
	if err = denyEscapes(); err != nil {
		return err
	}
	return syscall.Exec(command, append([]string{spec.Command}, spec.Args...), commandEnvironment(spec.Workspace))
}

func denyEscapes() error {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return errors.New("unsupported seccomp architecture")
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: arch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	// x32 numbers cannot bypass the native syscall deny list.
	if runtime.GOARCH == "amd64" {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS})
	}
	for _, call := range []uint32{unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_PIDFD_GETFD, unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL, unix.SYS_USERFAULTFD, unix.SYS_SETSID, unix.SYS_SETPGID} {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: call, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, err := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	if err != 0 {
		return err
	}
	return nil
}
