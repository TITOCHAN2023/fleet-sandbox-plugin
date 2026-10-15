package sandbox

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
)

type demandRunView interface {
	Checkpoint(context.Context) ([]string, error)
	BeforeHashes() map[string]string
	InitialEntries() []overlay.Entry
	Hashes(context.Context) (map[string]string, []string, error)
	Close() error
}
type executionView struct {
	path    string
	before  map[string]string
	initial []overlay.Entry
	demand  demandRunView
}

func viewMode(mode string) (string, error) {
	if mode == "" || mode == "copy" {
		return "copy", nil
	}
	if mode == "demand" {
		return mode, nil
	}
	return "", errors.New("unsupported file view mode")
}
func prepareExecutionView(ctx context.Context, cfg Config, dir string, emit Emit) (*executionView, error) {
	mode, err := viewMode(cfg.ViewMode)
	if err != nil {
		return nil, err
	}
	v := &executionView{path: filepath.Join(dir, "view")}
	if mode == "copy" {
		v.before, err = snapshot(cfg.Root, v.path)
		return v, err
	}
	v.demand, err = openDemandRunView(cfg.Root, filepath.Join(dir, "file-store"), v.path, emit)
	if err != nil {
		return nil, err
	}
	v.initial = v.demand.InitialEntries()
	return v, nil
}
func (v *executionView) checkpoint(ctx context.Context) ([]string, error) {
	if v.demand == nil {
		return nil, nil
	}
	gaps, err := v.demand.Checkpoint(ctx)
	v.before = v.demand.BeforeHashes()
	return gaps, err
}
func (v *executionView) Close() error {
	if v.demand == nil {
		return nil
	}
	err := v.demand.Close()
	if err == nil {
		v.demand = nil
	}
	return err
}
