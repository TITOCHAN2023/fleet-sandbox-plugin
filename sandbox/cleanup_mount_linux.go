//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/filelock"
)

func cleanupWorkspaceMount(dir string) error {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()
	view := filepath.Join(dir, "view")
	found := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " - ", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[0])
		tail := strings.Fields(parts[1])
		if len(fields) < 5 || len(tail) < 1 {
			continue
		}
		mount := decodeMountPath(fields[4])
		if !contains(dir, mount) {
			continue
		}
		if mount != view || tail[0] != "fuse.fleet-workspace" {
			return errors.New("unexpected mounted filesystem in workspace; refusing removal")
		}
		found = true
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	if !found {
		return nil
	}
	release, err := filelock.Acquire(filepath.Join(dir, "file-store", "view.lock"))
	if err != nil {
		return errors.New("file view still active; cannot discard")
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, helper := range []string{"/usr/bin/fusermount3", "/usr/bin/fusermount"} {
		if _, err = os.Stat(helper); err != nil {
			continue
		}
		if err = exec.CommandContext(ctx, helper, "-u", "-z", "--", view).Run(); err != nil {
			return errors.New("failed to detach stopped workspace mount")
		}
		return nil
	}
	return errors.New("FUSE unmount helper unavailable")
}
func decodeMountPath(path string) string {
	return strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(path)
}
