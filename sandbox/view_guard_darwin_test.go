//go:build darwin

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMacSourceGuardDetectsRestoredMetadataAndRetainsInode(t *testing.T) {
	g, err := newLocalSourceGuard()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := g.Close(); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(t.TempDir(), "input")
	if err = os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Watch("input", f); err != nil {
		t.Fatal(err)
	}
	f.Close() // The guard must keep its own descriptor alive.
	before, err := g.Stamp("input")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, time.Now(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := g.Stamp("input")
	if err != nil || before == after {
		t.Fatalf("write with restored mtime missed: %v", err)
	}
	// A rename round trip leaves the same inode and content at the old path.
	if err = os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".moved", path); err != nil {
		t.Fatal(err)
	}
	rename, err := g.Stamp("input")
	if err != nil || rename == after {
		t.Fatalf("rename round trip missed: %v", err)
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Stamp("input"); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed guard accepted")
	}
}

func TestMacSourceGuardDrainsAllInodesAndConcurrentChecks(t *testing.T) {
	g, err := newLocalSourceGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	root := t.TempDir()
	stamps := map[string]string{}
	for i := 0; i < 130; i++ {
		name := fmt.Sprint(i)
		path := filepath.Join(root, name)
		if err = os.WriteFile(path, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		err = g.Watch(name, f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		stamps[name], err = g.Stamp(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	for name := range stamps {
		if err = os.WriteFile(filepath.Join(root, name), []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for name, before := range stamps {
		wg.Add(1)
		go func(name, before string) {
			defer wg.Done()
			after, err := g.Stamp(name)
			if err != nil || after == before {
				t.Errorf("missed inode %s: %v", name, err)
			}
		}(name, before)
	}
	wg.Wait()
}
