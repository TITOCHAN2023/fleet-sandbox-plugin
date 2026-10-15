package sandbox

// File workspaces receive inert data. They run no program and make no claim
// about native process isolation or OS syscall trace coverage.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/filelock"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

const FileWorkspaceChunkBytes = 32 << 10

var syncFileWorkspaceDirectory = syncFileWorkspaceDirectoryPlatform

type FileWorkspaceSpec struct {
	ID      string `json:"workspace_id"`
	Binding string `json:"binding"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}
type FileWorkspaceState struct {
	FileWorkspaceSpec
	Offset       int64  `json:"offset"`
	PrefixSHA256 string `json:"prefix_sha256"`
	Complete     bool   `json:"complete"`
	Encrypted    bool   `json:"encrypted_persistence"`
}
type FileWorkspaceRequest struct {
	V           int               `json:"v"`
	Nonce       string            `json:"nonce"`
	Action      string            `json:"action"`
	Spec        FileWorkspaceSpec `json:"spec"`
	ID          string            `json:"workspace_id"`
	Offset      int64             `json:"offset"`
	Data        []byte            `json:"data,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Context     Invocation        `json:"context"`
}

type fileWorkspace struct {
	state   FileWorkspaceState
	objects *vault.Objects
	dir     string
	release func()
	prefix  hash.Hash
	ctx     context.Context
}

func fileDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func fileHashOK(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func fileWorkspaceRoot() (string, error) {
	root, e := dataDir()
	if e != nil {
		return "", e
	}
	dir := filepath.Join(root, "file-workspaces")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("unsafe file workspace directory")
	}
	if e = syncFileWorkspaceDirectory(root); e != nil {
		return "", e
	}
	return dir, nil
}
func lockFileWorkspace(id string) (*fileWorkspace, error) {
	if !fileHashOK(id) {
		return nil, errors.New("invalid file workspace id")
	}
	root, e := fileWorkspaceRoot()
	if e != nil {
		return nil, e
	}
	release, e := filelock.Acquire(filepath.Join(root, id+".lock"))
	if e != nil {
		return nil, e
	}
	dir := filepath.Join(root, id)
	if e = os.MkdirAll(dir, 0700); e != nil {
		release()
		return nil, e
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		release()
		return nil, errors.New("unsafe file workspace")
	}
	objects, e := vault.OpenObjectsStrict(dir, storageCipher.Load())
	if e != nil {
		release()
		return nil, e
	}
	return &fileWorkspace{dir: dir, release: release, objects: objects}, nil
}
func (f *fileWorkspace) key(kind string) string {
	return "file-workspace/" + filepath.Base(f.dir) + "/" + kind
}
func (f *fileWorkspace) chunkKey(offset int64) string { return f.key(fmt.Sprintf("chunk/%d", offset)) }
func (f *fileWorkspace) load() error {
	b, e := f.objects.Read(f.key("state"))
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &f.state); e != nil {
		return e
	}
	s := f.state
	if s.ID != filepath.Base(f.dir) || !fileHashOK(s.Binding) || !fileHashOK(s.SHA256) || !fileWorkspaceNameOK(s.Name) || s.Size < 0 || s.Size > 1<<53-1 || s.Offset < 0 || s.Offset > s.Size || (s.Offset != s.Size && s.Offset%FileWorkspaceChunkBytes != 0) || !fileHashOK(s.PrefixSHA256) || (s.Complete && (s.Offset != s.Size || s.PrefixSHA256 != s.SHA256)) {
		return errors.New("invalid file workspace checkpoint")
	}
	return nil
}
func (f *fileWorkspace) persist(state FileWorkspaceState) error {
	b, e := json.Marshal(state)
	if e != nil {
		return e
	}
	if e = f.objects.Write(f.key("state"), b); e != nil {
		return e
	}
	if e = syncFileWorkspaceDirectory(f.dir); e != nil {
		return e
	}
	f.state = state
	return nil
}
func (f *fileWorkspace) verify(w io.Writer) error {
	h := sha256.New()
	for offset := int64(0); offset < f.state.Offset; offset += FileWorkspaceChunkBytes {
		if f.ctx != nil {
			if e := f.ctx.Err(); e != nil {
				return e
			}
		}
		b, e := f.objects.Read(f.chunkKey(offset))
		if e != nil {
			return fmt.Errorf("workspace prefix unavailable: %w", e)
		}
		size := int64(FileWorkspaceChunkBytes)
		if remaining := f.state.Offset - offset; remaining < size {
			size = remaining
		}
		if int64(len(b)) != size {
			return errors.New("workspace prefix chunk length changed")
		}
		h.Write(b)
		if w != nil {
			if _, e = w.Write(b); e != nil {
				return e
			}
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != f.state.PrefixSHA256 {
		return errors.New("workspace prefix changed; discard or recover explicitly")
	}
	f.prefix = h
	return nil
}
func fileWorkspaceNameOK(name string) bool {
	if name == "" || !utf8.ValidString(name) || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\:<>\"|?*") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	stem := strings.ToUpper(strings.TrimRight(strings.Split(name, ".")[0], " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
		return false
	}
	// Win32 also treats the superscript 1/2/3 forms as device aliases.
	for _, prefix := range []string{"COM", "LPT"} {
		for _, suffix := range []string{"¹", "²", "³"} {
			if stem == prefix+suffix {
				return false
			}
		}
	}
	return true
}
func validFileWorkspaceSpec(s FileWorkspaceSpec) bool {
	return fileHashOK(s.ID) && fileHashOK(s.Binding) && fileHashOK(s.SHA256) && s.Size >= 0 && s.Size <= 1<<53-1 && fileWorkspaceNameOK(s.Name)
}
func openFileWorkspace(s FileWorkspaceSpec) (*fileWorkspace, error) {
	return openFileWorkspaceContext(context.Background(), s)
}
func openFileWorkspaceContext(ctx context.Context, s FileWorkspaceSpec) (*fileWorkspace, error) {
	if !validFileWorkspaceSpec(s) {
		return nil, errors.New("invalid file workspace specification")
	}
	f, e := lockFileWorkspace(s.ID)
	if e != nil {
		return nil, e
	}
	f.ctx = ctx
	keep := false
	defer func() {
		if !keep {
			f.release()
		}
	}()
	e = f.load()
	if os.IsNotExist(e) {
		// State is mandatory if any data objects exist. Never bless an orphaned
		// chunk set with a new manifest after checkpoint loss.
		entries, err := os.ReadDir(f.dir)
		if err != nil {
			return nil, err
		}
		if len(entries) != 0 {
			return nil, errors.New("workspace checkpoint missing; existing objects require explicit recovery")
		}
		f.prefix = sha256.New()
		e = f.persist(FileWorkspaceState{FileWorkspaceSpec: s, PrefixSHA256: fileDigest(nil), Encrypted: f.objects.Encrypted()})
		if e == nil {
			e = syncFileWorkspaceDirectory(filepath.Dir(f.dir))
		}
	} else if e == nil {
		if f.state.Encrypted != f.objects.Encrypted() {
			return nil, errors.New("workspace encryption migration required on the local page")
		}
		if f.state.FileWorkspaceSpec != s {
			return nil, errors.New("workspace binding or manifest changed")
		}
		e = f.verify(nil)
	}
	if e != nil {
		return nil, e
	}
	keep = true
	return f, nil
}
func (f *fileWorkspace) append(offset int64, b []byte, digest string) error {
	if f.state.Complete || offset != f.state.Offset || len(b) == 0 || len(b) > FileWorkspaceChunkBytes || !fileHashOK(digest) || fileDigest(b) != digest {
		return errors.New("invalid workspace chunk")
	}
	expected := int64(FileWorkspaceChunkBytes)
	if remaining := f.state.Size - offset; remaining < expected {
		expected = remaining
	}
	if int64(len(b)) != expected {
		return errors.New("workspace chunk does not match declared size")
	}
	// An unacknowledged crash tail is immutable. Replaying identical data is
	// safe; changed source data cannot silently fill or replace it.
	old, e := f.objects.Read(f.chunkKey(offset))
	if e == nil && !bytes.Equal(old, b) {
		return errors.New("unacknowledged workspace chunk changed")
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if os.IsNotExist(e) {
		if e = f.objects.Write(f.chunkKey(offset), b); e != nil {
			return e
		}
	}
	if e = syncFileWorkspaceDirectory(f.dir); e != nil {
		return e
	}
	f.prefix.Write(b)
	state := f.state
	state.Offset += int64(len(b))
	state.PrefixSHA256 = hex.EncodeToString(f.prefix.Sum(nil))
	return f.persist(state)
}
func (f *fileWorkspace) complete() error {
	if f.state.Offset != f.state.Size || f.state.PrefixSHA256 != f.state.SHA256 {
		return errors.New("workspace is incomplete or checksum mismatched")
	}
	if e := f.verify(nil); e != nil {
		return e
	}
	state := f.state
	state.Complete = true
	return f.persist(state)
}
func (f *fileWorkspace) export(destination string) (any, error) {
	if !f.state.Complete {
		return nil, errors.New("only complete workspaces can be exported")
	}
	if !filepath.IsAbs(destination) {
		return nil, errors.New("export directory must be absolute")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(destination)))
	if e != nil {
		return nil, e
	}
	destination = filepath.Join(parent, filepath.Base(filepath.Clean(destination)))
	root, e := dataDir()
	if e != nil {
		return nil, e
	}
	if contains(root, destination) {
		return nil, errors.New("export must be outside plugin storage")
	}
	if _, e = os.Lstat(destination); !os.IsNotExist(e) {
		return nil, errors.New("export destination already exists or is unavailable")
	}
	temp, e := os.MkdirTemp(parent, ".fleet-file-export-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(temp)
	out, e := os.OpenFile(filepath.Join(temp, f.state.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	e = f.verify(out)
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return nil, e
	}
	if e = syncFileWorkspaceDirectory(temp); e != nil {
		return nil, e
	}
	if e = publishDirectory(temp, destination); e != nil {
		return nil, e
	}
	if e = syncFileWorkspaceDirectory(parent); e != nil {
		return nil, e
	}
	return map[string]any{"workspace_id": f.state.ID, "destination": destination, "size": f.state.Size, "sha256": f.state.SHA256}, nil
}

// ServeFileWorkspaces is a bounded, nonce-authenticated stdio file service.
// InitStorage must succeed before calling it; its invocation key is scoped by
// Core to the calling plugin, and each object purpose includes workspace ID.
func serveFileWorkspaces(ctx context.Context, req FileWorkspaceRequest, active **fileWorkspace, emit Emit) (any, error) {
	if emit == nil {
		emit = func(string, string, string, map[string]any) {}
	}
	switch req.Action {
	case "hello":
		return map[string]any{"service": "fleet.file-workspace.v1", "chunk_bytes": FileWorkspaceChunkBytes, "executes_programs": false, "os_trace": false}, nil
	case "open":
		if *active != nil {
			return nil, errors.New("workspace already open")
		}
		f, e := openFileWorkspaceContext(ctx, req.Spec)
		if e != nil {
			return nil, e
		}
		*active = f
		emit("workspace", "opened", f.state.ID, map[string]any{"encrypted_persistence": f.state.Encrypted, "observation": "controlled_file_io"})
		return f.state, nil
	case "append":
		if *active == nil {
			return nil, errors.New("open workspace first")
		}
		if e := (*active).append(req.Offset, req.Data, req.SHA256); e != nil {
			return nil, e
		}
		return (*active).state, nil
	case "complete":
		if *active == nil {
			return nil, errors.New("open workspace first")
		}
		if e := (*active).complete(); e != nil {
			return nil, e
		}
		emit("workspace", "received", (*active).state.ID, map[string]any{"size": (*active).state.Size, "observation": "controlled_file_io"})
		return (*active).state, nil
	case "list":
		root, e := fileWorkspaceRoot()
		if e != nil {
			return nil, e
		}
		entries, e := os.ReadDir(root)
		if e != nil {
			return nil, e
		}
		states := []any{}
		busy := 0
		truncated := false
		for _, entry := range entries {
			if !entry.IsDir() || !fileHashOK(entry.Name()) {
				continue
			}
			if len(states) >= 256 {
				truncated = true
				break
			}
			f, e := lockFileWorkspace(entry.Name())
			if e != nil {
				busy++
				continue
			}
			e = f.load()
			f.release()
			if e != nil {
				states = append(states, map[string]any{"workspace_id": entry.Name(), "encrypted_persistence": false, "needs_inspection": true, "requires_encryption_migration": storageCipher.Load() != nil, "error": "checkpoint unavailable or requires local encryption migration"})
				continue
			}
			if f.state.Encrypted != f.objects.Encrypted() {
				states = append(states, map[string]any{"workspace_id": entry.Name(), "encrypted_persistence": false, "requires_encryption_migration": true})
				continue
			}
			states = append(states, f.state)
		}
		return map[string]any{"workspaces": states, "busy": busy, "truncated": truncated}, nil
	case "inspect", "export", "discard", "encrypt":
		if req.Action != "inspect" && req.Context.Origin != "local" {
			return nil, errors.New("workspace export/discard requires actual local origin")
		}
		if *active != nil {
			return nil, errors.New("workspace operation while receive session is active")
		}
		f, e := lockFileWorkspace(req.ID)
		if e != nil {
			return nil, e
		}
		defer f.release()
		f.ctx = ctx
		if req.Action == "discard" {
			if e = os.RemoveAll(f.dir); e != nil {
				return nil, e
			}
			if e = syncFileWorkspaceDirectory(filepath.Dir(f.dir)); e != nil {
				return nil, e
			}
			emit("workspace", "discarded", req.ID, nil)
			return map[string]bool{"ok": true}, nil
		}
		if req.Action == "encrypt" {
			cipher := storageCipher.Load()
			if cipher == nil {
				return nil, errors.New("enable and unlock device encryption first")
			}
			if e = f.objects.EnableEncryptionContext(ctx, cipher); e != nil {
				return nil, e
			}
			if e = f.load(); e != nil {
				return nil, e
			}
			if e = f.verify(nil); e != nil {
				return nil, e
			}
			state := f.state
			state.Encrypted = true
			if e = f.persist(state); e != nil {
				return nil, e
			}
			emit("workspace", "encrypted", req.ID, nil)
			return state, nil
		}
		if e = f.load(); e != nil {
			return nil, e
		}
		if f.state.Encrypted != f.objects.Encrypted() {
			return nil, errors.New("workspace encryption migration required on the local page")
		}
		if req.Action == "inspect" {
			if e = f.verify(nil); e != nil {
				return nil, e
			}
			return f.state, nil
		}
		result, e := f.export(req.Destination)
		if e == nil {
			emit("workspace", "exported", req.ID, map[string]any{"destination": req.Destination, "observation": "controlled_file_io"})
		}
		return result, e
	default:
		return nil, errors.New("unknown file workspace action")
	}
}
func closeFileWorkspace(active **fileWorkspace) {
	if *active != nil {
		(*active).release()
		*active = nil
	}
}

// FileWorkspaceSession hides the private lock holder from broker callers.
type FileWorkspaceSession struct {
	active  *fileWorkspace
	Context context.Context
}

func (s *FileWorkspaceSession) Handle(req FileWorkspaceRequest, emit Emit) (any, error) {
	ctx := s.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return serveFileWorkspaces(ctx, req, &s.active, emit)
}
func (s *FileWorkspaceSession) Close() { closeFileWorkspace(&s.active) }
