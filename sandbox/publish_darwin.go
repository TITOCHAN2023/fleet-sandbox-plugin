//go:build darwin

package sandbox

import "golang.org/x/sys/unix"

func publishDirectory(source, destination string) error {
	return unix.RenamexNp(source, destination, unix.RENAME_EXCL)
}
