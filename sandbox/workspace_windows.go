//go:build windows

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func finalFilePath(f *os.File) (string, error) {
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buf)) {
		return "", errors.New("workspace path too long")
	}
	return strings.ToLower(windows.UTF16ToString(buf[:n])), nil
}
func openWorkspaceFile(root, rel string) (*os.File, error) {
	if !filepath.IsLocal(rel) {
		return nil, errors.New("invalid workspace path")
	}
	rootFile, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer rootFile.Close()
	canonical, err := finalFilePath(rootFile)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	reject := func() (*os.File, error) {
		f.Close()
		return nil, errors.New("workspace file is not a single regular file within its root")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return reject()
	}
	actual, err := finalFilePath(f)
	if err != nil || !contains(canonical, actual) {
		return reject()
	}
	var native windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &native) != nil || native.NumberOfLinks != 1 || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return reject()
	}
	return f, nil
}
func publishDirectory(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
