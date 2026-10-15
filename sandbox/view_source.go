package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
)

type localViewSource struct {
	root  string
	guard *localSourceGuard
}

func newLocalViewSource(root string) (*localViewSource, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) {
		return nil, fs.ErrInvalid
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, fs.ErrInvalid
	}
	guard, err := newLocalSourceGuard()
	if err != nil {
		return nil, err
	}
	return &localViewSource{root: root, guard: guard}, nil
}
func (s *localViewSource) Close() error { return s.guard.Close() }
func (s *localViewSource) version(name string, f *os.File) (string, error) {
	stamp, err := s.guard.Stamp(name)
	if err != nil {
		return "", err
	}
	v, err := viewFileVersion(f)
	if err != nil {
		return "", err
	}
	return v + stamp, nil
}
func (s *localViewSource) Identity() (string, error) {
	sum := sha256.Sum256([]byte("local/" + s.root))
	return hex.EncodeToString(sum[:]), nil
}
func (s *localViewSource) Snapshot(ctx context.Context) ([]overlay.Entry, error) {
	entries := []overlay.Entry{}
	total := int64(0)
	err := filepath.WalkDir(s.root, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(s.root, full)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if len(entries) >= overlay.MaxEntries {
			return overlay.ErrQuota
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			entries = append(entries, overlay.Entry{Path: filepath.ToSlash(rel), Mode: info.Mode(), Version: "directory", MTime: info.ModTime().UnixNano()})
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("view source rejects links and special files")
		}
		f, err := openWorkspaceFile(s.root, rel)
		if err != nil {
			return err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(info, opened) {
			return overlay.ErrSourceChanged
		}
		if err = s.guard.Watch(filepath.ToSlash(rel), f); err != nil {
			return err
		}
		version, err := s.version(filepath.ToSlash(rel), f)
		if err != nil {
			return err
		}
		opened, err = f.Stat()
		if err != nil {
			return err
		}
		checkVersion, err := s.version(filepath.ToSlash(rel), f)
		if err != nil {
			return err
		}
		if checkVersion != version {
			return overlay.ErrSourceChanged
		}
		if opened.Size() < 0 || opened.Size() > overlay.MaxBytes-total {
			return overlay.ErrQuota
		}
		total += opened.Size()
		entries = append(entries, overlay.Entry{Path: filepath.ToSlash(rel), Size: opened.Size(), Mode: opened.Mode(), Version: version, MTime: opened.ModTime().UnixNano()})
		return nil
	})
	return entries, err
}
func (s *localViewSource) ReadAt(ctx context.Context, name, version string, b []byte, offset int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if offset < 0 || !filepath.IsLocal(filepath.FromSlash(name)) {
		return 0, fs.ErrInvalid
	}
	f, err := openWorkspaceFile(s.root, filepath.FromSlash(name))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	before, err := s.version(name, f)
	if err != nil {
		return 0, err
	}
	if before != version {
		return 0, overlay.ErrSourceChanged
	}
	n, err := f.ReadAt(b, offset)
	after, checkErr := s.version(name, f)
	if checkErr != nil || after != version {
		clear(b)
		return 0, overlay.ErrSourceChanged
	}
	if err != nil && !errors.Is(err, io.EOF) {
		clear(b)
		return 0, err
	}
	return n, err
}
