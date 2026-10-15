//go:build darwin || windows

package sandbox

import (
	"errors"
	"path/filepath"
)

func cleanupWorkspaceMount(dir string) error {
	state, err := loadWorkspace(dir)
	if err != nil {
		return err
	}
	if state.ViewMode == "demand" {
		return errors.New("demand mount cleanup is not available on this platform: " + filepath.Base(dir))
	}
	return nil
}
