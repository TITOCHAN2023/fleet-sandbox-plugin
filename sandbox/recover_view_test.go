package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

func TestInterruptedDemandWorkspaceRecoversOnlyOwnedBlocks(t *testing.T) {
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input"), []byte("old input"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := vault.New(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	SetStorageCipher(c)
	defer SetStorageCipher(nil)
	id := "99999999999999999999999999999999"
	dir, release, err := lockedWorkspace(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source, err := newLocalViewSource(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := overlay.Open(context.Background(), filepath.Join(dir, "file-store"), source, c)
	if err != nil {
		t.Fatal(err)
	}
	initial := v.InitialEntries()
	if err = v.Create("output", 0600); err != nil {
		t.Fatal(err)
	}
	h, _ := v.OpenFile("output")
	if _, err = h.WriteAt(context.Background(), []byte("retained result"), 0); err != nil {
		t.Fatal(err)
	}
	h.Close()
	v.Close()
	state := Workspace{ID: id, State: "running", Created: time.Now().UnixMilli(), InputRoot: root, ViewMode: "demand", Initial: initial, Encrypted: true}
	if err = saveWorkspace(dir, state); err != nil {
		t.Fatal(err)
	}
	release()
	if err = os.WriteFile(filepath.Join(root, "input"), []byte("new owner input"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := inspectWorkspace(id)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "interrupted" || len(result.RecoveryGaps) != 1 || result.RecoveryGaps[0] != "input" {
		t.Fatalf("invalid recovery: %+v", result)
	}
	for _, change := range result.Changes {
		if change.Path == "input" {
			t.Fatal("unavailable file mislabeled as deletion")
		}
	}
	dest := filepath.Join(t.TempDir(), "export")
	out, err := exportWorkspace(context.Background(), ExportInput{ID: id, Destination: dest}, func(string, string, string, map[string]any) {})
	if err != nil || !out.Incomplete || len(out.RecoveryGaps) != 1 || !out.InputUnavailable {
		t.Fatalf("partial export not identified: %+v %v", out, err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "files", "output"))
	if err != nil || string(b) != "retained result" {
		t.Fatal("owned output lost")
	}
	if _, err = os.Stat(filepath.Join(dest, "files", "input")); !os.IsNotExist(err) {
		t.Fatal("current source was mixed into recovery")
	}
	b, _ = os.ReadFile(filepath.Join(dest, "manifest.json"))
	var manifest map[string]any
	if json.Unmarshal(b, &manifest) != nil || manifest["incomplete"] != true {
		t.Fatal("manifest hid recovery gap")
	}
}

func TestStorageMigrationEncryptsExistingDemandBlocks(t *testing.T) {
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	SetStorageCipher(nil)
	defer SetStorageCipher(nil)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	id := "88888888888888888888888888888888"
	dir, release, err := lockedWorkspace(id)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source, err := newLocalViewSource(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := overlay.Open(context.Background(), filepath.Join(dir, "file-store"), source, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Create("result", 0600); err != nil {
		t.Fatal(err)
	}
	h, _ := v.OpenFile("result")
	if _, err = h.WriteAt(context.Background(), []byte("private legacy output"), 0); err != nil {
		t.Fatal(err)
	}
	h.Close()
	state := Workspace{ID: id, State: "interrupted", InputRoot: root, ViewMode: "demand", Initial: v.InitialEntries()}
	v.Close()
	if err = saveWorkspace(dir, state); err != nil {
		t.Fatal(err)
	}
	c, err := vault.New(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	SetStorageCipher(c)
	if err = protectWorkspace(dir); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(dir, "file-store"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".obj" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "file-store", file.Name()))
		if err != nil || !bytes.HasPrefix(b, []byte("FLEETENC1")) || bytes.Contains(b, []byte("private legacy")) {
			t.Fatal("legacy demand object not encrypted")
		}
	}
}
