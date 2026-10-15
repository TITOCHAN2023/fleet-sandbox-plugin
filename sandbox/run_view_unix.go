//go:build linux || darwin

package sandbox

import (
	"context"
	"errors"
	"runtime"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
)

type demandMountedView struct{ mount *mountedFileView }

func openDemandRunView(source, store, mount string, emit Emit) (demandRunView, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("demand file view requires the validated Linux source event guard; macOS backend is not ready")
	}
	m, err := mountFileView(source, store, mount, emit)
	if err != nil {
		return nil, err
	}
	return &demandMountedView{mount: m}, nil
}
func (v *demandMountedView) Checkpoint(ctx context.Context) ([]string, error) {
	return v.mount.view.Checkpoint(ctx)
}
func (v *demandMountedView) Hashes(ctx context.Context) (map[string]string, []string, error) {
	return v.mount.view.Hashes(ctx)
}
func (v *demandMountedView) BeforeHashes() map[string]string { return v.mount.view.BeforeHashes() }
func (v *demandMountedView) InitialEntries() []overlay.Entry { return v.mount.view.InitialEntries() }
func (v *demandMountedView) Close() error                    { return v.mount.Close() }
