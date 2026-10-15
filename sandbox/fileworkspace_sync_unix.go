//go:build !windows

package sandbox

import "os"

func syncFileWorkspaceDirectoryPlatform(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
