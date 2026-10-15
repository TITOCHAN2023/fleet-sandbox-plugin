//go:build windows

package sandbox

// vault.WriteAtomic uses MOVEFILE_WRITE_THROUGH on Windows. Directory fsync
// is not exposed there; the broker still waits for the durable replacement.
func syncFileWorkspaceDirectoryPlatform(string) error { return nil }
