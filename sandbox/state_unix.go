//go:build !windows

package sandbox

import "os"

func replaceState(from, to string) error { return os.Rename(from, to) }
