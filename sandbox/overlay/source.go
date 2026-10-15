// Package overlay owns a copy-on-write file view. Native filesystem adapters
// (FUSE/ProjFS) project this same state; task programs never receive lower paths
// or storage keys. Sources must reject links and detect changed file versions.
package overlay

import (
	"context"
	"errors"
	"io"
	"io/fs"
)

var (
	ErrSourceChanged = errors.New("source file changed since view creation")
	ErrQuota         = errors.New("workspace file quota exceeded")
)

type Entry struct {
	Path    string      `json:"path"`
	Size    int64       `json:"size"`
	Mode    fs.FileMode `json:"mode"`
	Version string      `json:"version"`
	ID      string      `json:"id,omitempty"`
	MTime   int64       `json:"mtime,omitempty"`
	ATime   int64       `json:"atime,omitempty"`
	CTime   int64       `json:"ctime,omitempty"`
}

// Snapshot enumerates metadata only. ReadAt may fetch data locally or remotely;
// on a version mismatch it must return no data and ErrSourceChanged.
type Source interface {
	Identity() (string, error)
	Snapshot(context.Context) ([]Entry, error)
	ReadAt(context.Context, string, string, []byte, int64) (int, error)
}

func readBase(ctx context.Context, source Source, node *node, buffer []byte, offset int64) error {
	clear(buffer)
	if node.BasePath == "" || offset >= node.BaseSize {
		return nil
	}
	n := int64(len(buffer))
	if node.BaseSize-offset < n {
		n = node.BaseSize - offset
	}
	read, err := source.ReadAt(ctx, node.BasePath, node.BaseVersion, buffer[:n], offset)
	if err != nil && err != io.EOF {
		clear(buffer)
		return err
	}
	if int64(read) != n {
		clear(buffer)
		return io.ErrUnexpectedEOF
	}
	return nil
}
