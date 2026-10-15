package sandbox

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveRejectsOversizedEntryBeforeExtraction(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	_, err := w.CreateRaw(&zip.FileHeader{Name: "huge", Method: zip.Store, UncompressedSize64: ^uint64(0), CompressedSize64: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err = extractZip(r, target); err == nil {
		t.Fatal("oversized archive accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("oversized archive created output")
	}
}

func TestWorkspaceSealingRestoresExportWithoutPersistentPlaintext(t *testing.T) {
	id, _, view := workspaceFixture(t)
	dir := filepath.Dir(view)
	c, _ := vault.New(bytes.Repeat([]byte{42}, 32))
	SetStorageCipher(c)
	defer SetStorageCipher(nil)
	if err := os.WriteFile(filepath.Join(view, "private.txt"), []byte("private fixture content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "syscalls.log"), []byte("private trace fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	req := Request{Action: "encrypt_storage", Context: Invocation{Origin: "local"}}
	if _, err := Handle(context.Background(), req, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"view", "syscalls.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("plaintext remained: " + name)
		}
	}
	for _, name := range []string{"view.enc", "trace.enc", "workspace.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("private fixture")) {
			t.Fatal("archive contained plaintext")
		}
	}
	restored, cleanup, err := materializeView(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(restored, "private.txt"))
	if err != nil || string(b) != "private fixture content" {
		t.Fatal("restore lost content")
	}
	cleanup()
	if _, err = os.Stat(restored); !os.IsNotExist(err) {
		t.Fatal("materialized view was retained")
	}
	input, _ := json.Marshal(ExportInput{id, filepath.Join(t.TempDir(), "export")})
	result, err := Handle(context.Background(), Request{Action: "export", Input: input, Context: Invocation{Origin: "local"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := result.(ExportResult)
	b, err = os.ReadFile(filepath.Join(out.Destination, "files", "private.txt"))
	if err != nil || string(b) != "private fixture content" {
		t.Fatal("export lost content")
	}
	SetStorageCipher(nil)
	if _, err = loadWorkspace(dir); err == nil {
		t.Fatal("encrypted state opened without key")
	}
}
func TestEncryptedArchiveRefusesTamperedContent(t *testing.T) {
	_, _, view := workspaceFixture(t)
	dir := filepath.Dir(view)
	c, _ := vault.New(bytes.Repeat([]byte{42}, 32))
	SetStorageCipher(c)
	defer SetStorageCipher(nil)
	if err := sealView(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "view.enc")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = materializeView(dir); err == nil {
		t.Fatal("tampered archive materialized")
	}
}
