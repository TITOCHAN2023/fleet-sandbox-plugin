//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var userenv = windows.NewLazySystemDLL("userenv.dll")
var createContainer = userenv.NewProc("CreateAppContainerProfile")
var deleteContainer = userenv.NewProc("DeleteAppContainerProfile")

const securityCapabilitiesAttribute = uintptr(0x20009)

// PROC_THREAD_ATTRIBUTE_JOB_LIST (WinBase.h), supported on Windows 10 /
// Server 2016 and newer. x/sys v0.34.0 does not expose this constant.
const jobListAttribute = uintptr(0x2000d)

type securityCapabilities struct {
	SID             *windows.SID
	Capabilities    *windows.SIDAndAttributes
	Count, Reserved uint32
}

func NativeProbe() Capability {
	err := createContainer.Find()
	reason := "AppContainer API unavailable"
	if err == nil {
		var job windows.Handle
		var attrs *windows.ProcThreadAttributeListContainer
		job, attrs, err = newNativeJobAttributes()
		if err == nil {
			attrs.Delete()
			windows.CloseHandle(job)
		} else {
			reason = err.Error()
		}
	}
	cap := Capability{ProcessTreeContainment: err == nil, Backend: "windows-appcontainer-job", Available: err == nil, FilesystemIsolation: err == nil, NetworkDenied: err == nil}
	if err != nil {
		cap.Reason = reason
	}
	return cap
}
func NativeChild(Spec) error { return errors.New("native child entry is Linux-only") }

func newNativeJobAttributes() (windows.Handle, *windows.ProcThreadAttributeListContainer, error) {
	job, err := windows.CreateJobObject(nil, nil) // The child must not inherit the job handle.
	if err != nil {
		return 0, nil, fmt.Errorf("create sandbox job: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, nil, fmt.Errorf("configure sandbox job: %w", err)
	}
	attrs, err := windows.NewProcThreadAttributeList(3) // AppContainer, inherited stdio, and atomic job assignment.
	if err != nil {
		windows.CloseHandle(job)
		return 0, nil, err
	}
	jobs := [1]windows.Handle{job}
	// Update retains the value pointer until Delete. Never fall back to assigning
	// after CreateProcess: broker death in that gap leaves a suspended child.
	if err = attrs.Update(jobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs)); err != nil {
		attrs.Delete()
		windows.CloseHandle(job)
		return 0, nil, fmt.Errorf("atomic sandbox job assignment requires Windows 10 / Server 2016 or newer: %w", err)
	}
	return job, attrs, nil
}

func grantWorkspace(root string, sid *windows.SID) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;" + sid.String() + ")S:(ML;OICI;NW;;;LW)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("workspace link rejected")
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION, nil, nil, dacl, sacl)
	})
}

func NativeRun(ctx context.Context, spec Spec, emit Emit) (int, string, string, error) {
	return nativeRun(ctx, spec, emit, nil)
}
func nativeRun(ctx context.Context, spec Spec, emit Emit, streams *Streams) (int, string, string, error) {
	command, err := exec.LookPath(spec.Command)
	if err != nil {
		return -1, "", "", err
	}
	name, err := windows.UTF16PtrFromString("FleetSandbox." + filepath.Base(filepath.Dir(spec.Workspace)))
	if err != nil {
		return -1, "", "", err
	}
	var sid *windows.SID
	code, _, _ := createContainer.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if int32(code) < 0 {
		return -1, "", "", fmt.Errorf("create AppContainer: HRESULT 0x%x", code)
	}
	defer deleteContainer.Call(uintptr(unsafe.Pointer(name)))
	defer windows.FreeSid(sid)
	// All mutations below are restricted to the private workspace. Host input
	// directories and executables never receive weaker ACLs.
	commandEnvironment(spec.Workspace)
	if err = grantWorkspace(spec.Workspace, sid); err != nil {
		return -1, "", "", fmt.Errorf("workspace ACL: %w", err)
	}
	job, attrs, err := newNativeJobAttributes()
	if err != nil {
		return -1, "", "", err
	}
	defer windows.CloseHandle(job)
	defer attrs.Delete()
	caps := securityCapabilities{SID: sid}
	if err = attrs.Update(securityCapabilitiesAttribute, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
		return -1, "", "", err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return -1, "", "", err
	}
	defer stdoutR.Close()
	defer stdoutW.Close()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		return -1, "", "", err
	}
	defer stderrR.Close()
	defer stderrW.Close()
	var stdin *os.File
	if streams != nil {
		stdin = streams.Stdin
	}
	if stdin == nil {
		stdin, err = os.Open(os.DevNull)
		if err != nil {
			return -1, "", "", err
		}
		defer stdin.Close()
	}
	handles := []windows.Handle{windows.Handle(stdin.Fd()), windows.Handle(stdoutW.Fd()), windows.Handle(stderrW.Fd())}
	for _, handle := range handles {
		if err = windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return -1, "", "", err
		}
		defer windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, 0)
	}
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return -1, "", "", err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
	application, err := windows.UTF16PtrFromString(command)
	if err != nil {
		return -1, "", "", err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{command}, spec.Args...)))
	if err != nil {
		return -1, "", "", err
	}
	cwd, err := windows.UTF16PtrFromString(spec.CWD)
	if err != nil {
		return -1, "", "", err
	}
	envValues := commandEnvironment(spec.Workspace)
	sort.Slice(envValues, func(i, j int) bool { return strings.ToUpper(envValues[i]) < strings.ToUpper(envValues[j]) })
	var environment []uint16
	for _, value := range envValues {
		encoded, e := windows.UTF16FromString(value)
		if e != nil {
			return -1, "", "", e
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)

	pi := windows.ProcessInformation{}
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err = windows.CreateProcess(application, line, nil, nil, true, flags, &environment[0], cwd, &si.StartupInfo, &pi); err != nil {
		return -1, "", "", fmt.Errorf("start AppContainer (tool must be executable within Windows capabilities): %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	runtime.KeepAlive(caps)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(environment)
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return -1, "", "", err
	}
	_ = stdoutW.Close()
	_ = stderrW.Close()
	out, errOut := &cappedOutput{}, &cappedOutput{}
	var outWriter, errWriter io.Writer = out, errOut
	if streams != nil {
		if streams.Stdout != nil {
			outWriter = io.MultiWriter(out, streams.Stdout)
		}
		if streams.Stderr != nil {
			errWriter = io.MultiWriter(errOut, streams.Stderr)
		}
	}
	var drains sync.WaitGroup
	copyErrors := make(chan error, 2)
	drains.Add(2)
	drain := func(dst io.Writer, src io.Reader) {
		defer drains.Done()
		_, copyErr := io.Copy(dst, src)
		if copyErr != nil {
			_ = windows.TerminateJobObject(job, 1)
		}
		copyErrors <- copyErr
	}
	go drain(outWriter, stdoutR)
	go drain(errWriter, stderrR)
	emit("process", "started", spec.Command, map[string]any{"pid": pi.ProcessId, "backend": "appcontainer", "observation": "launcher"})
	done := make(chan error, 1)
	go func() { _, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE); done <- err }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = windows.TerminateJobObject(job, 1)
		<-done
		err = ctx.Err()
	}
	_ = windows.TerminateJobObject(job, 0)
	drains.Wait()
	err = errors.Join(err, <-copyErrors, <-copyErrors)
	var exit uint32
	if e := windows.GetExitCodeProcess(pi.Process, &exit); e != nil && err == nil {
		err = e
	}
	emit("process", "exited", spec.Command, map[string]any{"pid": pi.ProcessId, "exit_code": int(exit)})
	return int(exit), out.b.String(), errOut.b.String(), err
}
