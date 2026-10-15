//go:build windows

package sandbox

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exercise the actual creation boundary: do not resume the child or assign it
// afterward. Closing the launcher's only job handle must reap it even here.
func TestNativeJobAssignmentPrecedesResume(t *testing.T) {
	job, attrs, err := newNativeJobAttributes()
	if err != nil {
		t.Fatal(err)
	}
	defer attrs.Delete()
	defer func() {
		if job != 0 {
			windows.CloseHandle(job)
		}
	}()

	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
		t.Fatal(err)
	}
	if limits.BasicLimitInformation.LimitFlags != windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE {
		t.Fatalf("job permits escape or lacks kill-on-close: flags %#x", limits.BasicLimitInformation.LimitFlags)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		t.Fatal(err)
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{executable}))
	if err != nil {
		t.Fatal(err)
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))}, ProcThreadAttributeList: attrs.List()}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(application, line, nil, nil, false, windows.CREATE_SUSPENDED|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi); err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	defer windows.TerminateProcess(pi.Process, 1) // Reap a failed regression too.

	// JOBOBJECT_BASIC_PROCESS_ID_LIST with room for the sole child.
	var processes struct {
		Assigned uint32
		Count    uint32
		PID      [1]uintptr
	}
	if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&processes)), uint32(unsafe.Sizeof(processes)), nil); err != nil {
		t.Fatal(err)
	}
	if processes.Assigned != 1 || processes.Count != 1 || processes.PID[0] != uintptr(pi.ProcessId) {
		t.Fatalf("suspended child was created outside its job: %+v, child PID %d", processes, pi.ProcessId)
	}
	if err := windows.CloseHandle(job); err != nil {
		t.Fatal(err)
	}
	job = 0
	status, err := windows.WaitForSingleObject(pi.Process, 5000)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("suspended child survived closing its job: wait %#x, error %v", status, err)
	}
}
