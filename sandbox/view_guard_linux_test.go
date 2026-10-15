//go:build linux

package sandbox

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestDemandSourceDoesNotTreatRemoteMountsAsLocalEventSources(t *testing.T) {
	for _, kind := range []int64{unix.NFS_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, 0} {
		if supportsLocalSourceEvents(kind) {
			t.Errorf("unsupported filesystem %x accepted", kind)
		}
	}
}
