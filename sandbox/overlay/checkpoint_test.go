package overlay

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointRecoversWithoutReadingCurrentSource(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	dir := t.TempDir()
	c := cipherFixture(t)
	v, err := Open(ctx, dir, source, c)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := v.OpenFile("a")
	if _, err = h.WriteAt(ctx, []byte("owned output"), 0); err != nil {
		t.Fatal(err)
	}
	h.Close()
	gaps, err := v.Checkpoint(ctx)
	if err != nil || len(gaps) != 0 {
		t.Fatalf("checkpoint: %v %v", gaps, err)
	}
	before := v.BeforeHashes()
	if len(before) != 1 || len(before["a"]) != 64 {
		t.Fatal("input digest missing")
	}
	v.Close()
	source.entries[0].Version = "changed"
	source.data["a"] = bytes.Repeat([]byte("new"), len(source.data["a"]))
	v, err = OpenOffline(ctx, dir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	h, _ = v.OpenFile("a")
	defer h.Close()
	b := make([]byte, 12)
	if _, err = h.ReadAt(ctx, b, 0); err != nil || string(b) != "owned output" {
		t.Fatal("recovery consulted changed source")
	}
	target := filepath.Join(t.TempDir(), "files")
	gaps, err = v.Materialize(ctx, target)
	if err != nil || len(gaps) != 0 {
		t.Fatal("complete view did not materialize")
	}
	data, err := os.ReadFile(filepath.Join(target, "a"))
	if err != nil || string(data[:12]) != "owned output" {
		t.Fatal("materialized output lost")
	}
}
func TestOfflineRecoveryReportsMissingSourceInsteadOfMixingNewData(t *testing.T) {
	ctx := context.Background()
	source := sourceFixture()
	dir := t.TempDir()
	c := cipherFixture(t)
	v, err := Open(ctx, dir, source, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Create("result", 0600); err != nil {
		t.Fatal(err)
	}
	h, _ := v.OpenFile("result")
	if _, err = h.WriteAt(ctx, []byte("retained output"), 0); err != nil {
		t.Fatal(err)
	}
	h.Close()
	v.Close()
	v, err = OpenOffline(ctx, dir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	target := filepath.Join(t.TempDir(), "files")
	gaps, err := v.Materialize(ctx, target)
	if err != nil || len(gaps) != 1 || gaps[0] != "a" {
		t.Fatalf("missing source not reported: %v %v", gaps, err)
	}
	if _, err = os.Stat(filepath.Join(target, "a")); !os.IsNotExist(err) {
		t.Fatal("partial source file published")
	}
	data, err := os.ReadFile(filepath.Join(target, "result"))
	if err != nil || string(data) != "retained output" {
		t.Fatal("new output not recovered")
	}
}
