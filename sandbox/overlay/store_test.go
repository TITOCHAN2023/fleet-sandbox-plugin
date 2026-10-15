package overlay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

type fixtureSource struct {
	identity string
	entries  []Entry
	data     map[string][]byte
	reads    atomic.Int64
}

func (s *fixtureSource) Identity() (string, error)                 { return s.identity, nil }
func (s *fixtureSource) Snapshot(context.Context) ([]Entry, error) { return s.entries, nil }
func (s *fixtureSource) ReadAt(_ context.Context, name, version string, b []byte, offset int64) (int, error) {
	s.reads.Add(1)
	for _, entry := range s.entries {
		if entry.Path == name && entry.Version != version {
			return 0, ErrSourceChanged
		}
	}
	data := s.data[name]
	if offset >= int64(len(data)) {
		return 0, io.EOF
	}
	n := copy(b, data[offset:])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}
func sourceFixture() *fixtureSource {
	data := bytes.Repeat([]byte("synthetic private source content\n"), BlockBytes/32+7)
	return &fixtureSource{identity: "source-a", entries: []Entry{{Path: "a", Size: int64(len(data)), Mode: 0600, Version: "v1"}}, data: map[string][]byte{"a": data}}
}
func cipherFixture(t *testing.T) *vault.Cipher {
	t.Helper()
	c, err := vault.New(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDemandReadEncryptedWriteRenameDeleteAndRestart(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	dir := t.TempDir()
	cipher := cipherFixture(t)
	v, err := Open(ctx, dir, source, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if source.reads.Load() != 0 {
		t.Fatal("view creation read file contents")
	}
	h, err := v.OpenFile("a")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if n, err := h.ReadAt(ctx, b, 0); err != nil || n != 5 || string(b) != "synth" {
		t.Fatal("demand read failed")
	}
	if source.reads.Load() != 1 {
		t.Fatal("read fetched unrelated blocks")
	}
	if _, err := h.WriteAt(ctx, []byte("PRIVATE"), 2); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source.data["a"], []byte("PRIVATE")) {
		t.Fatal("write changed source")
	}
	for _, file := range mustReadDir(t, dir) {
		if !strings.HasSuffix(file.Name(), ".obj") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("PRIVATE")) || bytes.Contains(data, []byte("synthetic private")) {
			t.Fatal("plaintext persisted")
		}
	}
	if err = v.Rename("a", "renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Stat("a"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("old name survived rename")
	}
	b = make([]byte, 9)
	if _, err = h.ReadAt(ctx, b, 0); err != nil || string(b) != "syPRIVATE" {
		t.Fatal("open handle lost rename")
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v, err = Open(ctx, dir, source, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	h, err = v.OpenFile("renamed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadAt(ctx, b, 0); err != nil || string(b) != "syPRIVATE" {
		t.Fatal("restart lost write")
	}
	if err = v.Remove("renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadAt(ctx, b, 0); err != nil {
		t.Fatal("unlink invalidated open handle")
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if len(v.state.Nodes) != 1 {
		t.Fatal("unlinked node not reclaimed")
	}
	count := 0
	for _, file := range mustReadDir(t, dir) {
		if strings.HasSuffix(file.Name(), ".obj") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("unlinked data blocks not reclaimed: %d", count)
	}
}
func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestTruncateAndRegrowCannotRevealDiscardedBytes(t *testing.T) {
	ctx := context.Background()
	v, err := Open(ctx, t.TempDir(), sourceFixture(), cipherFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	h, err := v.OpenFile("a")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err = h.Truncate(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err = h.Truncate(ctx, BlockBytes*2+3); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, BlockBytes*2+3)
	if _, err = h.ReadAt(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if string(b[:5]) != "synth" || bytes.Count(b[5:], []byte{0}) != len(b)-5 {
		t.Fatal("truncate exposed old contents")
	}
}
func TestQuotaAndNamesFailBeforeSourceReadOrMetadataCommit(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	v, err := Open(ctx, t.TempDir(), source, cipherFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, name := range []string{"../escape", "/outside", ".git/config", "dir\\child", "a/../b", "", "."} {
		if err = v.Create(name, 0600); err == nil {
			t.Fatal("invalid path accepted: " + name)
		}
	}
	h, _ := v.OpenFile("a")
	defer h.Close()
	if _, err = h.WriteAt(ctx, []byte("x"), MaxBytes); !errors.Is(err, ErrQuota) {
		t.Fatal("oversized write accepted")
	}
	if source.reads.Load() != 0 {
		t.Fatal("invalid operation read lower data")
	}
	if err = h.Truncate(ctx, MaxBytes); err != nil {
		t.Fatal(err)
	}
	if err = v.Create("new", 0600); err != nil {
		t.Fatal(err)
	}
	other, _ := v.OpenFile("new")
	defer other.Close()
	if _, err = other.WriteAt(ctx, []byte("x"), 0); !errors.Is(err, ErrQuota) {
		t.Fatal("aggregate quota not enforced")
	}
	entry, _ := v.Stat("new")
	if entry.Size != 0 {
		t.Fatal("quota failure committed partial size")
	}
}
func TestSourceMismatchAndChangedVersionDoNotReturnData(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	dir := t.TempDir()
	c := cipherFixture(t)
	v, err := Open(ctx, dir, source, c)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := v.OpenFile("a")
	source.entries[0].Version = "v2"
	b := bytes.Repeat([]byte{42}, 10)
	if n, err := h.ReadAt(ctx, b, 0); n != 0 || !errors.Is(err, ErrSourceChanged) {
		t.Fatal("changed source returned data")
	}
	h.Close()
	v.Close()
	source.identity = "other-source"
	if v, err = Open(ctx, dir, source, c); err == nil {
		v.Close()
		t.Fatal("view rebound to other source")
	}
}
func TestViewLockAndConcurrentIOKeepOneWriter(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	dir := t.TempDir()
	c := cipherFixture(t)
	v, err := Open(ctx, dir, source, c)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if another, err := Open(ctx, dir, source, c); err == nil {
		another.Close()
		t.Fatal("second writer opened view")
	}
	h, _ := v.OpenFile("a")
	defer h.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := h.WriteAt(ctx, []byte{byte(i)}, int64(i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	b := make([]byte, 8)
	if _, err = h.ReadAt(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		if b[i] != byte(i) {
			t.Fatal("concurrent write lost data")
		}
	}
}

func TestConcurrentAppendKeepsEveryRecord(t *testing.T) {
	ctx := context.Background()
	source := &fixtureSource{identity: "empty-source"}
	v, err := Open(ctx, t.TempDir(), source, cipherFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err = v.Create("log", 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h, err := v.OpenFile("log")
			if err != nil {
				t.Error(err)
				return
			}
			defer h.Close()
			for j := 0; j < 5; j++ {
				if _, err = h.Append(ctx, []byte{byte(i)}); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	h, _ := v.OpenFile("log")
	defer h.Close()
	b := make([]byte, 40)
	if _, err = h.ReadAt(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if bytes.Count(b, []byte{byte(i)}) != 5 {
			t.Fatal("append lost or replaced a record")
		}
	}
}

func TestRestartReclaimsUncommittedBlocksWithoutLosingCommittedData(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	dir := t.TempDir()
	cipher := cipherFixture(t)
	v, err := Open(ctx, dir, source, cipher)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := v.OpenFile("a")
	if _, err = h.WriteAt(ctx, []byte("saved"), 0); err != nil {
		t.Fatal(err)
	}
	h.Close()
	v.Close()
	objects, err := vault.OpenObjects(dir, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err = objects.Write("block/"+strings.Repeat("f", 32), bytes.Repeat([]byte{1}, BlockBytes)); err != nil {
		t.Fatal(err)
	}
	v, err = Open(ctx, dir, source, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	h, _ = v.OpenFile("a")
	defer h.Close()
	b := make([]byte, 5)
	if _, err = h.ReadAt(ctx, b, 0); err != nil || string(b) != "saved" {
		t.Fatal("recovery lost committed data")
	}
	count := 0
	for _, file := range mustReadDir(t, dir) {
		if strings.HasSuffix(file.Name(), ".obj") {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("orphan block survived recovery: %d", count)
	}
}
