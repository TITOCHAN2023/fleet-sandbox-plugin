package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

func TestLocalDemandSourceHasNoWriteThroughAndRejectsOwnerEdits(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a")
	original := bytes.Repeat([]byte("original fixture"), 8192)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := newLocalViewSource(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	c, err := vault.New(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v, err := overlay.Open(context.Background(), t.TempDir(), source, c)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	h, err := v.OpenFile("a")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err = h.WriteAt(context.Background(), []byte("private output"), 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(b, original) {
		t.Fatal("write reached original file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Repeat([]byte("changed! fixture"), 8192)
	if len(changed) != len(original) {
		t.Fatal("fixture must keep same size")
	}
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, time.Now(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	b = make([]byte, 8)
	if _, err = h.ReadAt(context.Background(), b, 0); err != nil || string(b) != "private " {
		t.Fatal("owner edit damaged written block")
	}
	if n, err := h.ReadAt(context.Background(), b, overlay.BlockBytes); n != 0 || !errors.Is(err, overlay.ErrSourceChanged) {
		t.Fatal("same-size owner edit with restored mtime leaked into view")
	}
}
func TestLocalViewSnapshotRejectsLinksAndHidesGit(t *testing.T) {
	root := t.TempDir()
	git := filepath.Join(root, ".git")
	if err := os.Mkdir(git, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(git, "secret-config"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := newLocalViewSource(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	entries, err := source.Snapshot(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Path != "regular" {
		t.Fatal("git metadata exposed")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip(err)
	}
	if _, err = source.Snapshot(context.Background()); err == nil {
		t.Fatal("source link accepted")
	}
	if err = os.Remove(filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(outside, filepath.Join(root, "hard")); err != nil {
		t.Skip(err)
	}
	if _, err = source.Snapshot(context.Background()); err == nil {
		t.Fatal("source hard link accepted")
	}
	if _, err = source.ReadAt(context.Background(), "../outside", "version", make([]byte, 5), 0); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal("source traversal accepted")
	}
}
