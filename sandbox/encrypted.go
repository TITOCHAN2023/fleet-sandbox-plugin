package sandbox

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

var storageCipher atomic.Pointer[vault.Cipher]

func InitStorage(ctx context.Context) error {
	c, err := vault.InvocationCipher(ctx)
	if err == nil {
		storageCipher.Store(c)
	}
	return err
}
func SetStorageCipher(c *vault.Cipher) { storageCipher.Store(c) }
func statePurpose(path string) (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errors.New("state path outside plugin storage")
	}
	return "state/" + filepath.ToSlash(rel), nil
}
func writeState(path string, b []byte) error {
	if c := storageCipher.Load(); c != nil {
		purpose, err := statePurpose(path)
		if err != nil {
			return err
		}
		b, err = c.Seal(purpose, b)
		if err != nil {
			return err
		}
	}
	return atomicWrite(path, b)
}
func readState(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, errors.New("invalid plugin state file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(b, []byte("FLEETENC1")) {
		return b, nil
	}
	c := storageCipher.Load()
	if c == nil {
		return nil, vault.ErrLocked
	}
	purpose, err := statePurpose(path)
	if err != nil {
		return nil, err
	}
	return c.Open(purpose, b)
}

const archiveMax = snapshotMax + (64 << 20)

func archivePurpose(dir string) string { return "workspace/" + filepath.Base(dir) + "/view" }
func writeZip(root string, w io.Writer) error {
	archive := zip.NewWriter(w)
	total := int64(0)
	count := 0
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		count++
		if count > 10000 {
			return errors.New("workspace archive entry limit exceeded")
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return errors.New("workspace archive rejects links and special files")
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		header.Method = zip.Store
		if info.IsDir() {
			header.Name += "/"
			_, err = archive.CreateHeader(header)
			return err
		}
		total += info.Size()
		if total > snapshotMax {
			return errors.New("workspace archive exceeds 512 MiB")
		}
		in, err := openWorkspaceFile(root, rel)
		if err != nil {
			return err
		}
		defer in.Close()
		opened, err := in.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return errors.New("workspace changed during sealing")
		}
		out, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(in, info.Size()+1))
		if err != nil {
			return err
		}
		after, err := in.Stat()
		if err != nil || n != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			return errors.New("workspace changed during sealing")
		}
		return nil
	})
	closeErr := archive.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func sealView(dir string) error {
	if err := sealMountedView(dir); err != nil {
		return err
	}
	if storageCipher.Load() == nil {
		return nil
	}
	return os.RemoveAll(filepath.Join(dir, "view"))
}

// Persist/authenticate the archive without unlinking files in a live mount.
func sealMountedView(dir string) error {
	c := storageCipher.Load()
	if c == nil {
		return nil
	}
	root := filepath.Join(dir, "view")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	out, err := os.CreateTemp(dir, ".sealed-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { e := writeZip(root, writer); writer.CloseWithError(e); done <- e }()
	err = c.SealStream(archivePurpose(dir), reader, out)
	reader.CloseWithError(err)
	producerErr := <-done
	if err == nil {
		err = producerErr
	}
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Authenticate the complete archive before deleting any original work files.
	verify, err := os.Open(out.Name())
	if err != nil {
		return err
	}
	err = c.OpenStream(archivePurpose(dir), verify, io.Discard, archiveMax)
	verify.Close()
	if err != nil {
		return err
	}
	if err = replaceState(out.Name(), filepath.Join(dir, "view.enc")); err != nil {
		return err
	}
	return nil
}
func sealTrace(dir string) error {
	c := storageCipher.Load()
	if c == nil {
		return nil
	}
	path := filepath.Join(dir, "syscalls.log")
	original, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !original.Mode().IsRegular() || original.Size() > 64<<20 {
		return errors.New("invalid trace archive")
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(original, info) {
		return errors.New("invalid trace archive")
	}
	out, err := os.CreateTemp(dir, ".trace-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	err = c.SealStream("workspace/"+filepath.Base(dir)+"/trace", io.LimitReader(f, 64<<20), out)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	verify, err := os.Open(out.Name())
	if err != nil {
		return err
	}
	err = c.OpenStream("workspace/"+filepath.Base(dir)+"/trace", verify, io.Discard, 64<<20)
	verify.Close()
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return errors.New("trace changed during sealing")
	}
	f.Close()
	if err = replaceState(out.Name(), filepath.Join(dir, "trace.enc")); err != nil {
		return err
	}
	return os.Remove(path)
}
func materializeView(dir string) (string, func(), error) {
	root := filepath.Join(dir, "view")
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		return root, func() {}, nil
	}
	c := storageCipher.Load()
	if c == nil {
		return "", nil, vault.ErrLocked
	}
	archivePath := filepath.Join(dir, "view.enc")
	archiveInfo, err := os.Lstat(archivePath)
	if err != nil {
		return "", nil, err
	}
	if !archiveInfo.Mode().IsRegular() || archiveInfo.Size() > archiveMax+(1<<20) {
		return "", nil, errors.New("invalid sealed archive")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(archiveInfo, opened) {
		return "", nil, errors.New("sealed archive changed while opening")
	}
	temp, err := os.MkdirTemp(dir, ".materialized-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(temp) }
	decoded, err := os.CreateTemp(temp, ".archive-")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	err = c.OpenStream(archivePurpose(dir), f, decoded, archiveMax)
	if err != nil {
		decoded.Close()
		cleanup()
		return "", nil, err
	}
	info, err := decoded.Stat()
	if err != nil {
		decoded.Close()
		cleanup()
		return "", nil, err
	}
	archive, err := zip.NewReader(decoded, info.Size())
	if err != nil {
		decoded.Close()
		cleanup()
		return "", nil, err
	}
	target := filepath.Join(temp, "files")
	if err = os.Mkdir(target, 0700); err != nil {
		decoded.Close()
		cleanup()
		return "", nil, err
	}
	err = extractZip(archive, target)
	decoded.Close()
	os.Remove(decoded.Name())
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return target, cleanup, nil
}
func extractZip(archive *zip.Reader, target string) error {
	if len(archive.File) > 10000 {
		return errors.New("archive entry limit exceeded")
	}
	var total uint64
	seen := map[string]bool{}
	for _, entry := range archive.File {
		name := strings.TrimSuffix(entry.Name, "/")
		if !filepath.IsLocal(filepath.FromSlash(name)) || seen[name] || entry.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid archive path")
		}
		seen[name] = true
		path := filepath.Join(target, filepath.FromSlash(name))
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0700); err != nil {
				return err
			}
			continue
		}
		if !entry.Mode().IsRegular() {
			return errors.New("special archive entry")
		}
		if entry.UncompressedSize64 > uint64(snapshotMax)-total {
			return errors.New("archive output exceeds 512 MiB")
		}
		total += entry.UncompressedSize64
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		in, err := entry.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, entry.Mode().Perm()&0700)
		if err != nil {
			in.Close()
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(in, int64(entry.UncompressedSize64)+1))
		in.Close()
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if uint64(n) != entry.UncompressedSize64 {
			return errors.New("archive size mismatch")
		}
	}
	return nil
}

func protectStoredWorkspaces(req Request, emit Emit) (any, error) {
	if req.Context.Origin != "local" {
		return nil, errors.New("storage migration requires the local device page")
	}
	if storageCipher.Load() == nil {
		return nil, errors.New("enable and unlock device encryption first")
	}
	storage, err := dataDir()
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"config.json"} {
		path := filepath.Join(storage, name)
		b, e := readState(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if e = writeState(path, b); e != nil {
			return nil, e
		}
	}
	entries, err := os.ReadDir(filepath.Join(storage, "workspaces"))
	if os.IsNotExist(err) {
		return map[string]any{"sealed": 0, "busy": 0}, nil
	}
	if err != nil {
		return nil, err
	}
	sealed, busy := 0, 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir, release, err := lockedWorkspace(entry.Name())
		if err != nil {
			busy++
			continue
		}
		err = protectWorkspace(dir)
		release()
		if err != nil {
			return nil, err
		}
		sealed++
	}
	emit("workspace", "encrypted", "Stored workspace migration", map[string]any{"sealed": sealed, "busy": busy})
	return map[string]any{"sealed": sealed, "busy": busy}, nil
}
func protectWorkspace(dir string) error {
	state, stateErr := loadWorkspace(dir)
	if stateErr != nil {
		return stateErr
	}
	if state.ViewMode == "demand" {
		v, err := overlay.OpenOffline(context.Background(), filepath.Join(dir, "file-store"), storageCipher.Load())
		if err != nil {
			return err
		}
		if err = v.Close(); err != nil {
			return err
		}
	}
	for _, name := range []string{"workspace.json", "result.json"} {
		path := filepath.Join(dir, name)
		b, err := readState(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = writeState(path, b); err != nil {
			return err
		}
	}
	if err := sealTrace(dir); err != nil {
		return err
	}
	if err := sealView(dir); err != nil {
		return err
	}
	if b, err := readState(filepath.Join(dir, "result.json")); err == nil {
		var result Result
		if err = json.Unmarshal(b, &result); err != nil {
			return err
		}
		result.Encrypted = true
		b, _ = json.Marshal(result)
		if err = writeState(filepath.Join(dir, "result.json"), b); err != nil {
			return err
		}
	}
	if state, err := loadWorkspace(dir); err == nil {
		state.Encrypted = true
		return saveWorkspace(dir, state)
	}
	return nil
}
