package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

func fileWorkspaceFixture(t *testing.T, data []byte) FileWorkspaceSpec {
	t.Helper()
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	SetStorageCipher(nil)
	t.Cleanup(func() { SetStorageCipher(nil) })
	return FileWorkspaceSpec{ID: fileDigest([]byte("slot")), Binding: fileDigest([]byte("manifest")), Name: "received.bin", Size: int64(len(data)), SHA256: fileDigest(data)}
}
func appendFileWorkspace(t *testing.T, f *fileWorkspace, data []byte) {
	t.Helper()
	for offset := int64(0); offset < int64(len(data)); offset += FileWorkspaceChunkBytes {
		end := offset + FileWorkspaceChunkBytes
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		part := data[offset:end]
		if e := f.append(offset, part, fileDigest(part)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestFileWorkspaceReceiveResumeAndExport(t *testing.T) {
	data := bytes.Repeat([]byte("sample"), 20000)
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	first := data[:FileWorkspaceChunkBytes]
	if e = f.append(0, first, fileDigest(first)); e != nil {
		t.Fatal(e)
	}
	f.release()
	f, e = openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	if f.state.Offset != FileWorkspaceChunkBytes || f.state.PrefixSHA256 != fileDigest(first) {
		t.Fatal("durable checkpoint lost")
	}
	for offset := int64(FileWorkspaceChunkBytes); offset < int64(len(data)); offset += FileWorkspaceChunkBytes {
		end := offset + FileWorkspaceChunkBytes
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		part := data[offset:end]
		if e = f.append(offset, part, fileDigest(part)); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.complete(); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(t.TempDir(), "new-directory")
	if _, e = f.export(destination); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(destination, s.Name))
	if e != nil || !bytes.Equal(got, data) {
		t.Fatal("export bytes differ", e)
	}
	if _, e = f.export(destination); e == nil {
		t.Fatal("export overwrote existing directory")
	}
	f.release()
	f, e = openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	defer f.release()
	if !f.state.Complete {
		t.Fatal("complete receipt lost")
	}
}
func TestFileWorkspaceEmptyAndLargeDeclaredSize(t *testing.T) {
	s := fileWorkspaceFixture(t, nil)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.complete(); e != nil {
		t.Fatal(e)
	}
	f.release()
	s.ID = fileDigest([]byte("large"))
	s.Size = 10 << 30
	f, e = openFileWorkspace(s)
	if e != nil {
		t.Fatal("file store incorrectly inherited 512MiB archive ceiling", e)
	}
	f.release()
}
func TestFileWorkspaceBindingAndTamperedPrefixFailClosed(t *testing.T) {
	data := bytes.Repeat([]byte{3}, FileWorkspaceChunkBytes)
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	appendFileWorkspace(t, f, data)
	f.release()
	for _, changed := range []FileWorkspaceSpec{func() FileWorkspaceSpec { x := s; x.Binding = fileDigest([]byte("changed")); return x }(), func() FileWorkspaceSpec { x := s; x.SHA256 = fileDigest([]byte("changed")); return x }(), func() FileWorkspaceSpec { x := s; x.Name = "other"; return x }()} {
		if x, e := openFileWorkspace(changed); e == nil {
			x.release()
			t.Fatal("changed binding accepted")
		}
	}
	f, e = lockFileWorkspace(s.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.objects.Write(f.chunkKey(0), bytes.Repeat([]byte{4}, len(data))); e != nil {
		t.Fatal(e)
	}
	f.release()
	if f, e = openFileWorkspace(s); e == nil {
		f.release()
		t.Fatal("tampered prefix accepted")
	}
}
func TestFileWorkspaceUnacknowledgedChunkCannotBeChanged(t *testing.T) {
	data := bytes.Repeat([]byte{3}, FileWorkspaceChunkBytes)
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.objects.Write(f.chunkKey(0), data); e != nil {
		t.Fatal(e)
	}
	f.release()
	f, e = openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	defer f.release()
	changed := bytes.Repeat([]byte{4}, len(data))
	if e = f.append(0, changed, fileDigest(changed)); e == nil {
		t.Fatal("changed unacknowledged tail accepted")
	}
	if f.state.Offset != 0 {
		t.Fatal("failed chunk advanced checkpoint")
	}
	if e = f.append(0, data, fileDigest(data)); e != nil {
		t.Fatal("identical crash tail replay rejected", e)
	}
}
func TestFileWorkspaceHashFailureAndDurabilityFailure(t *testing.T) {
	data := []byte("payload")
	s := fileWorkspaceFixture(t, data)
	s.SHA256 = fileDigest([]byte("different"))
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	defer f.release()
	original := syncFileWorkspaceDirectory
	t.Cleanup(func() { syncFileWorkspaceDirectory = original })
	syncFileWorkspaceDirectory = func(string) error { return errors.New("injected sync failure") }
	if e = f.append(0, data, fileDigest(data)); e == nil {
		t.Fatal("chunk acknowledged despite sync failure")
	}
	if f.state.Offset != 0 {
		t.Fatal("failed durability step advanced checkpoint")
	}
	syncFileWorkspaceDirectory = original
	if e = f.append(0, data, fileDigest(data)); e != nil {
		t.Fatal(e)
	}
	if e = f.complete(); e == nil {
		t.Fatal("wrong final hash completed")
	}
}
func TestFileWorkspaceMissingCorruptStateCanOnlyBeDiscardedLocally(t *testing.T) {
	s := fileWorkspaceFixture(t, []byte("payload"))
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.objects.Remove(f.key("state")); e != nil {
		t.Fatal(e)
	}
	if e = f.objects.Write(f.chunkKey(0), []byte("payload")); e != nil {
		t.Fatal(e)
	}
	f.release()
	if f, e = openFileWorkspace(s); e == nil {
		f.release()
		t.Fatal("missing checkpoint silently recreated")
	}
	session := FileWorkspaceSession{}
	defer session.Close()
	for _, origin := range []string{"", "remote"} {
		if _, e = session.Handle(FileWorkspaceRequest{Action: "discard", ID: s.ID, Context: Invocation{Origin: origin}}, nil); e == nil {
			t.Fatal("nonlocal discard accepted")
		}
	}
	if _, e = session.Handle(FileWorkspaceRequest{Action: "discard", ID: s.ID, Context: Invocation{Origin: "local"}}, nil); e != nil {
		t.Fatal("explicit local cleanup cannot remove corrupt workspace", e)
	}
	if f, e = openFileWorkspace(s); e != nil {
		t.Fatal(e)
	} else {
		f.release()
	}
}
func TestFileWorkspaceEncryptionMigrationAndCrossWorkspaceCiphertextSwap(t *testing.T) {
	data := []byte("private bytes")
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	appendFileWorkspace(t, f, data)
	if e = f.complete(); e != nil {
		t.Fatal(e)
	}
	dir := f.dir
	f.release()
	cipher, e := vault.New(bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	SetStorageCipher(cipher)
	if f, e = openFileWorkspace(s); e == nil {
		f.release()
		t.Fatal("unencrypted store silently adopted")
	}
	session := FileWorkspaceSession{}
	defer session.Close()
	if _, e = session.Handle(FileWorkspaceRequest{Action: "list"}, nil); e != nil {
		t.Fatal("list should report migration requirement", e)
	}
	if _, e = session.Handle(FileWorkspaceRequest{Action: "encrypt", ID: s.ID, Context: Invocation{Origin: "remote"}}, nil); e == nil {
		t.Fatal("remote migrated encryption policy")
	}
	if _, e = session.Handle(FileWorkspaceRequest{Action: "encrypt", ID: s.ID, Context: Invocation{Origin: "local"}}, nil); e != nil {
		t.Fatal(e)
	}
	f, e = openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	if !f.state.Encrypted {
		t.Fatal("successful migration not reported")
	}
	f.release()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		if e != nil || !bytes.HasPrefix(b, []byte("FLEETENC1")) || bytes.Contains(b, data) {
			t.Fatal("plaintext persisted after migration", e)
		}
	}
	second := s
	second.ID = fileDigest([]byte("second-slot"))
	g, e := openFileWorkspace(second)
	if e != nil {
		t.Fatal(e)
	}
	appendFileWorkspace(t, g, data)
	key := func(id string) string { h := sha256.Sum256([]byte(id)); return hex.EncodeToString(h[:]) + ".obj" }
	sourcePath := filepath.Join(dir, key("file-workspace/"+s.ID+"/chunk/0"))
	targetPath := filepath.Join(g.dir, key(g.chunkKey(0)))
	b, e := os.ReadFile(sourcePath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(targetPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	g.release()
	if g, e = openFileWorkspace(second); e == nil {
		g.release()
		t.Fatal("cross-workspace ciphertext substitution accepted")
	}
}
func TestFileWorkspaceExportSymlinkAndBusyLock(t *testing.T) {
	s := fileWorkspaceFixture(t, []byte("file"))
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	defer f.release()
	appendFileWorkspace(t, f, []byte("file"))
	if e = f.complete(); e != nil {
		t.Fatal(e)
	}
	if other, e := openFileWorkspace(s); e == nil {
		other.release()
		t.Fatal("simultaneous receive acquired lock")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "link")
	existing := t.TempDir()
	if e = os.Symlink(existing, target); e != nil {
		t.Skip(e)
	}
	if _, e = f.export(target); e == nil {
		t.Fatal("export replaced symlink")
	}
	root, _ := dataDir()
	if _, e = f.export(filepath.Join(root, "export")); e == nil {
		t.Fatal("export exposed internal store")
	}
}
func TestFileWorkspaceRejectsCrossPlatformDeviceAndAliasNames(t *testing.T) {
	s := fileWorkspaceFixture(t, nil)
	for _, name := range []string{"NUL", "nul.txt", "CON .txt", "NUL .dat", "COM1 .txt", "LPT¹ .txt", "CON", "con.tar.gz", "COM1.log", "lpt9", "COM¹.txt", "LPT²", "CONIN$", "file:ads", "tail.", "tail ", "new\nline", "nul\x00byte", "../escape", "back\\slash", "a*b", "AUX", "PRN"} {
		changed := s
		changed.Name = name
		if f, e := openFileWorkspace(changed); e == nil {
			f.release()
			t.Fatalf("unsafe workspace filename accepted: %q", name)
		}
	}
	for _, name := range []string{"received.bin", "中文 文件.tar.gz", "normal-name", "COM10.txt", "NULL.txt"} {
		if !fileWorkspaceNameOK(name) {
			t.Fatalf("normal filename rejected: %q", name)
		}
	}
}
func TestFileWorkspaceCancellationStopsPrefixVerify(t *testing.T) {
	data := bytes.Repeat([]byte{1}, 2*FileWorkspaceChunkBytes)
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	appendFileWorkspace(t, f, data)
	f.release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f, e = openFileWorkspaceContext(ctx, s); e == nil {
		f.release()
		t.Fatal("canceled prefix verification continued")
	} else if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestFileWorkspaceObjectWriteFailureAndCorruptCheckpoint(t *testing.T) {
	data := []byte("payload")
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte(f.chunkKey(0)))
	path := filepath.Join(f.dir, hex.EncodeToString(h[:])+".obj")
	if e = os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e = f.append(0, data, fileDigest(data)); e == nil {
		t.Fatal("object write/read failure acknowledged")
	}
	if f.state.Offset != 0 {
		t.Fatal("object failure advanced offset")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = f.objects.Write(f.key("state"), []byte("{corrupt")); e != nil {
		t.Fatal(e)
	}
	f.release()
	if f, e = openFileWorkspace(s); e == nil {
		f.release()
		t.Fatal("corrupt state silently repaired")
	}
	session := FileWorkspaceSession{}
	defer session.Close()
	if _, e = session.Handle(FileWorkspaceRequest{Action: "discard", ID: s.ID, Context: Invocation{Origin: "local"}}, nil); e != nil {
		t.Fatal(e)
	}
}
func TestFileWorkspaceMigrationHonorsCanceledContext(t *testing.T) {
	data := bytes.Repeat([]byte{4}, 2*FileWorkspaceChunkBytes)
	s := fileWorkspaceFixture(t, data)
	f, e := openFileWorkspace(s)
	if e != nil {
		t.Fatal(e)
	}
	appendFileWorkspace(t, f, data)
	f.release()
	cipher, e := vault.New(bytes.Repeat([]byte{5}, 32))
	if e != nil {
		t.Fatal(e)
	}
	SetStorageCipher(cipher)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := FileWorkspaceSession{Context: ctx}
	defer session.Close()
	_, e = session.Handle(FileWorkspaceRequest{Action: "encrypt", ID: s.ID, Context: Invocation{Origin: "local"}}, nil)
	if !errors.Is(e, context.Canceled) {
		t.Fatal("migration ignored cancellation", e)
	}
}
