//go:build linux || darwin

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func openWorkspaceFile(root, rel string) (*os.File, error) {
	if !filepath.IsLocal(rel) {
		return nil, errors.New("invalid workspace path")
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), rel)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("workspace file must be regular")
	}
	if info.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return nil, errors.New("workspace hard links cannot be read or exported")
	}
	return f, nil
}
