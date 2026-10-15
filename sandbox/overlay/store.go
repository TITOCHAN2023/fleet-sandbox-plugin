package overlay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/filelock"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

const (
	BlockBytes = 64 << 10
	MaxBytes   = int64(512 << 20)
	MaxEntries = 10000
	MaxHandles = 1024
	MaxIOBytes = 1 << 20
)

type node struct {
	MTime       int64            `json:"mtime"`
	ATime       int64            `json:"atime"`
	CTime       int64            `json:"ctime"`
	Size        int64            `json:"size"`
	Mode        fs.FileMode      `json:"mode"`
	BasePath    string           `json:"base_path,omitempty"`
	BaseVersion string           `json:"base_version,omitempty"`
	BaseSize    int64            `json:"base_size,omitempty"`
	Blocks      map[int64]string `json:"blocks,omitempty"`
}
type state struct {
	Version int               `json:"version"`
	Source  string            `json:"source"`
	Paths   map[string]string `json:"paths"`
	Nodes   map[string]*node  `json:"nodes"`
	Initial map[string]Entry  `json:"initial"`
	Before  map[string]string `json:"before,omitempty"`
}
type View struct {
	mu      sync.Mutex
	source  Source
	objects *vault.Objects
	state   state
	handles map[string]int
	release func()
	closed  bool
}

func cleanName(name string) (string, error) {
	if name == "." {
		return name, nil
	}
	if len(name) > 1024 || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || name == "" {
		return "", fs.ErrInvalid
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".git" {
			return "", fs.ErrPermission
		}
	}
	return name, nil
}
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
func Open(ctx context.Context, dir string, source Source, cipher *vault.Cipher) (*View, error) {
	if source == nil {
		return nil, errors.New("file source required")
	}
	identity, err := source.Identity()
	if err != nil || identity == "" {
		return nil, errors.New("file source identity unavailable")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	release, err := filelock.Acquire(filepath.Join(dir, "view.lock"))
	if err != nil {
		return nil, err
	}
	objects, err := vault.OpenObjects(dir, cipher)
	if err != nil {
		release()
		return nil, err
	}
	v := &View{source: source, objects: objects, release: release, handles: map[string]int{}}
	b, err := objects.Read("index")
	if err == nil {
		if json.Unmarshal(b, &v.state) != nil {
			release()
			return nil, errors.New("invalid view state")
		}
		if err = validateState(v.state); err != nil {
			release()
			return nil, err
		}
		if v.state.Source != identity {
			release()
			return nil, errors.New("workspace source binding changed")
		}
		// A process restart releases every open handle. Unlinked files can now
		// be reclaimed without changing visible path or deletion semantics.
		next := cloneState(v.state)
		v.reclaimUnlinked(&next)
		if err = v.commit(next); err != nil {
			release()
			return nil, err
		}
		if err = v.reclaimOrphans(dir); err != nil {
			release()
			return nil, err
		}
		return v, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		release()
		return nil, err
	}
	entries, err := source.Snapshot(ctx)
	if err != nil {
		release()
		return nil, err
	}
	s := state{Version: 2, Source: identity, Paths: map[string]string{}, Nodes: map[string]*node{}, Initial: map[string]Entry{}, Before: map[string]string{}}
	id, err := randomID()
	if err != nil {
		release()
		return nil, err
	}
	s.Paths["."] = id
	s.Nodes[id] = &node{Mode: fs.ModeDir | 0700, MTime: time.Now().UnixNano(), CTime: time.Now().UnixNano()}
	for _, entry := range entries {
		name, e := cleanName(entry.Path)
		if e != nil || name == "." || s.Paths[name] != "" || (!entry.Mode.IsRegular() && !entry.Mode.IsDir()) || entry.Size < 0 || entry.Version == "" {
			release()
			return nil, errors.New("invalid source snapshot entry")
		}
		id, e := randomID()
		if e != nil {
			release()
			return nil, e
		}
		s.Paths[name] = id
		s.Initial[name] = entry
		s.Nodes[id] = &node{Size: entry.Size, Mode: entry.Mode.Type() | entry.Mode.Perm()&0700, BasePath: name, BaseVersion: entry.Version, BaseSize: entry.Size, MTime: entry.MTime, ATime: entry.ATime, CTime: entry.CTime}
	}
	if err = validateState(s); err != nil {
		release()
		return nil, err
	}
	if err = v.commit(s); err != nil {
		release()
		return nil, err
	}
	return v, nil
}

// A valid index and its held lock identify this directory as one view's store.
// Only unreferenced object files in this private store may be reclaimed.
func (v *View) reclaimOrphans(dir string) error {
	nameFor := func(id string) string { sum := sha256.Sum256([]byte(id)); return hex.EncodeToString(sum[:]) + ".obj" }
	live := map[string]bool{nameFor("index"): true}
	for _, n := range v.state.Nodes {
		for _, id := range n.Blocks {
			live[nameFor("block/"+id)] = true
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		name := file.Name()
		if filepath.Ext(name) != ".obj" || live[name] {
			continue
		}
		if len(name) != 68 {
			return errors.New("invalid view object file")
		}
		if _, err := hex.DecodeString(strings.TrimSuffix(name, ".obj")); err != nil {
			return err
		}
		info, err := file.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("view object is not regular")
		}
		if err = os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}
func validateState(s state) error {
	if s.Version != 2 || s.Source == "" || len(s.Source) > 256 || len(s.Paths) > MaxEntries+1 || len(s.Nodes) > MaxEntries+MaxHandles+1 || len(s.Initial) > MaxEntries || s.Initial == nil || s.Paths["."] == "" || s.Nodes[s.Paths["."]] == nil || !s.Nodes[s.Paths["."]].Mode.IsDir() {
		return errors.New("invalid view index")
	}
	var total int64
	blocks := 0
	seen := map[string]bool{}
	for name, entry := range s.Initial {
		if _, err := cleanName(name); err != nil || name == "." || entry.Path != name || entry.Size < 0 || entry.Size > MaxBytes || (!entry.Mode.IsRegular() && !entry.Mode.IsDir()) || entry.Version == "" || len(entry.Version) > 256 {
			return errors.New("invalid initial view metadata")
		}
	}
	for name, hash := range s.Before {
		entry, ok := s.Initial[name]
		if !ok || !entry.Mode.IsRegular() || len(hash) != 64 {
			return errors.New("invalid input digest")
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return err
		}
	}
	for name, id := range s.Paths {
		if _, err := cleanName(name); err != nil || !validID(id) || s.Nodes[id] == nil || seen[id] {
			return errors.New("invalid view path binding")
		}
		seen[id] = true
		if name != "." {
			parent := s.Nodes[s.Paths[path.Dir(name)]]
			if parent == nil || !parent.Mode.IsDir() {
				return errors.New("view parent directory missing")
			}
		}
	}
	for id, n := range s.Nodes {
		blocks += len(n.Blocks)
		if blocks > int(MaxBytes/BlockBytes) {
			return ErrQuota
		}
		if !validID(id) || n == nil || n.Size < 0 || n.BaseSize < 0 || n.Size > MaxBytes || n.BaseSize > MaxBytes || (!n.Mode.IsRegular() && !n.Mode.IsDir()) {
			return errors.New("invalid view node")
		}
		if n.Mode.IsDir() && len(n.Blocks) > 0 {
			return errors.New("directory contains data blocks")
		}
		if n.BasePath != "" {
			if _, err := cleanName(n.BasePath); err != nil || n.BaseVersion == "" {
				return errors.New("invalid lower binding")
			}
		}
		if len(n.BaseVersion) > 256 || n.BasePath == "" && (n.BaseVersion != "" || n.BaseSize != 0) {
			return errors.New("invalid lower version")
		}
		for offset, block := range n.Blocks {
			if offset < 0 || offset >= MaxBytes/BlockBytes || !validID(block) {
				return errors.New("invalid view block reference")
			}
		}
		if n.Mode.IsDir() {
			continue
		}
		if n.Size > MaxBytes-total {
			return ErrQuota
		}
		total += n.Size
	}
	return nil
}
func cloneState(s state) state {
	next := state{Version: s.Version, Source: s.Source, Paths: make(map[string]string, len(s.Paths)), Nodes: make(map[string]*node, len(s.Nodes)), Initial: s.Initial, Before: make(map[string]string, len(s.Before))}
	for k, v := range s.Before {
		next.Before[k] = v
	}
	for k, v := range s.Paths {
		next.Paths[k] = v
	}
	for k, v := range s.Nodes {
		next.Nodes[k] = v
	}
	return next
}
func cloneNode(n *node) *node {
	copy := *n
	copy.Blocks = make(map[int64]string, len(n.Blocks))
	for k, v := range n.Blocks {
		copy.Blocks[k] = v
	}
	return &copy
}
func (v *View) commit(s state) error {
	if err := validateState(s); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = v.objects.Write("index", b); err != nil {
		return err
	}
	old := v.state
	v.state = s
	live := map[string]bool{}
	for _, n := range s.Nodes {
		for _, id := range n.Blocks {
			live[id] = true
		}
	}
	for _, n := range old.Nodes {
		for _, id := range n.Blocks {
			if !live[id] {
				_ = v.objects.Remove("block/" + id)
			}
		}
	}
	return nil
}
func (v *View) reclaimUnlinked(s *state) {
	linked := map[string]bool{}
	for _, id := range s.Paths {
		linked[id] = true
	}
	for id := range s.Nodes {
		if !linked[id] && v.handles[id] == 0 {
			delete(s.Nodes, id)
		}
	}
}
func (v *View) lookup(name string) (string, *node, error) {
	if v.closed {
		return "", nil, fs.ErrClosed
	}
	name, err := cleanName(name)
	if err != nil {
		return "", nil, err
	}
	id := v.state.Paths[name]
	n := v.state.Nodes[id]
	if n == nil {
		return "", nil, fs.ErrNotExist
	}
	return id, n, nil
}
func nodeEntry(name, id string, n *node) Entry {
	return Entry{Path: name, ID: id, Size: n.Size, Mode: n.Mode, MTime: n.MTime, ATime: n.ATime, CTime: n.CTime}
}
func (v *View) Stat(name string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	id, n, err := v.lookup(name)
	if err != nil {
		return Entry{}, err
	}
	return nodeEntry(name, id, n), nil
}
func (v *View) ReadDir(name string) ([]Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, n, err := v.lookup(name)
	if err != nil {
		return nil, err
	}
	if !n.Mode.IsDir() {
		return nil, fs.ErrInvalid
	}
	entries := []Entry{}
	for p, id := range v.state.Paths {
		if p == "." || path.Dir(p) != name {
			continue
		}
		n := v.state.Nodes[id]
		entries = append(entries, nodeEntry(p, id, n))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
func (v *View) create(name string, mode fs.FileMode) error {
	if _, err := cleanName(name); err != nil || name == "." {
		return fs.ErrInvalid
	}
	if v.closed {
		return fs.ErrClosed
	}
	if v.state.Paths[name] != "" {
		return fs.ErrExist
	}
	parent := v.state.Nodes[v.state.Paths[path.Dir(name)]]
	if parent == nil || !parent.Mode.IsDir() {
		return fs.ErrNotExist
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	next := cloneState(v.state)
	next.Paths[name] = id
	next.Nodes[id] = &node{Mode: mode.Type() | mode.Perm()&0700, MTime: time.Now().UnixNano(), CTime: time.Now().UnixNano()}
	return v.commit(next)
}
func (v *View) Create(name string, mode fs.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !mode.IsRegular() {
		return fs.ErrPermission
	}
	return v.create(name, mode)
}
func (v *View) Mkdir(name string, mode fs.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.create(name, fs.ModeDir|mode.Perm())
}
func emptyDirectory(paths map[string]string, name string) bool {
	for p := range paths {
		if p != name && path.Dir(p) == name {
			return false
		}
	}
	return true
}
func (v *View) Remove(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, n, err := v.lookup(name)
	if err != nil {
		return err
	}
	if name == "." {
		return fs.ErrPermission
	}
	if n.Mode.IsDir() && !emptyDirectory(v.state.Paths, name) {
		return errors.New("directory not empty")
	}
	next := cloneState(v.state)
	delete(next.Paths, name)
	v.reclaimUnlinked(&next)
	return v.commit(next)
}
func (v *View) Rename(oldName, newName string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	id, n, err := v.lookup(oldName)
	if err != nil {
		return err
	}
	if _, err := cleanName(newName); err != nil || oldName == "." || newName == "." {
		return fs.ErrInvalid
	}
	if oldName == newName {
		return nil
	}
	if strings.HasPrefix(newName, oldName+"/") {
		return fs.ErrInvalid
	}
	parent := v.state.Nodes[v.state.Paths[path.Dir(newName)]]
	if parent == nil || !parent.Mode.IsDir() {
		return fs.ErrNotExist
	}
	if target := v.state.Nodes[v.state.Paths[newName]]; target != nil {
		if n.Mode.IsDir() != target.Mode.IsDir() || target.Mode.IsDir() && !emptyDirectory(v.state.Paths, newName) {
			return fs.ErrExist
		}
	}
	next := cloneState(v.state)
	delete(next.Paths, newName)
	for p, child := range v.state.Paths {
		if p == oldName || strings.HasPrefix(p, oldName+"/") {
			delete(next.Paths, p)
			next.Paths[newName+strings.TrimPrefix(p, oldName)] = child
		}
	}
	next.Paths[newName] = id
	v.reclaimUnlinked(&next)
	return v.commit(next)
}

type Handle struct {
	view   *View
	id     string
	closed bool
}

func (v *View) OpenFile(name string) (*Handle, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	id, n, err := v.lookup(name)
	if err != nil {
		return nil, err
	}
	if n.Mode.IsDir() {
		return nil, fs.ErrInvalid
	}
	count := 0
	for _, n := range v.handles {
		count += n
	}
	if count >= MaxHandles {
		return nil, ErrQuota
	}
	v.handles[id]++
	return &Handle{view: v, id: id}, nil
}
func (h *Handle) node() (*node, error) {
	if h.closed || h.view.closed {
		return nil, fs.ErrClosed
	}
	n := h.view.state.Nodes[h.id]
	if n == nil {
		return nil, fs.ErrNotExist
	}
	return n, nil
}
func (v *View) readBlock(ctx context.Context, n *node, index int64) ([]byte, error) {
	if id := n.Blocks[index]; id != "" {
		b, err := v.objects.Read("block/" + id)
		if err != nil {
			return nil, err
		}
		if len(b) != BlockBytes {
			return nil, errors.New("invalid data block")
		}
		return b, nil
	}
	b := make([]byte, BlockBytes)
	err := readBase(ctx, v.source, n, b, index*BlockBytes)
	return b, err
}
func (h *Handle) ReadAt(ctx context.Context, p []byte, offset int64) (int, error) {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := h.node()
	if err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > MaxIOBytes {
		return 0, ErrQuota
	}
	if offset >= n.Size {
		return 0, io.EOF
	}
	count := int64(len(p))
	if count > n.Size-offset {
		count = n.Size - offset
	}
	done := int64(0)
	for done < count {
		if err := ctx.Err(); err != nil {
			clear(p[:done])
			return 0, err
		}
		position := offset + done
		index := position / BlockBytes
		inBlock := position % BlockBytes
		b, err := v.readBlock(ctx, n, index)
		if err != nil {
			clear(p[:done])
			return 0, err
		}
		size := int64(BlockBytes) - inBlock
		if size > count-done {
			size = count - done
		}
		copy(p[done:done+size], b[inBlock:inBlock+size])
		clear(b)
		done += size
	}
	if done < int64(len(p)) {
		return int(done), io.EOF
	}
	return int(done), nil
}
func (h *Handle) WriteAt(ctx context.Context, p []byte, offset int64) (int, error) {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	return h.writeAt(ctx, p, offset)
}
func (h *Handle) Append(ctx context.Context, p []byte) (int, error) {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := h.node()
	if err != nil {
		return 0, err
	}
	return h.writeAt(ctx, p, n.Size)
}
func (h *Handle) writeAt(ctx context.Context, p []byte, offset int64) (int, error) {
	v := h.view
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := h.node()
	if err != nil {
		return 0, err
	}
	if offset < 0 || offset > MaxBytes || int64(len(p)) > MaxBytes-offset || len(p) > MaxIOBytes {
		return 0, ErrQuota
	}
	if len(p) == 0 {
		return 0, nil
	}
	next := cloneState(v.state)
	changed := cloneNode(n)
	next.Nodes[h.id] = changed
	changed.MTime, changed.CTime = time.Now().UnixNano(), time.Now().UnixNano()
	end := offset + int64(len(p))
	if end > changed.Size {
		changed.Size = end
	}
	if err = validateState(next); err != nil {
		return 0, err
	}
	created := []string{}
	replaced := []string{}
	committed := false
	defer func() {
		if !committed {
			for _, id := range created {
				_ = v.objects.Remove("block/" + id)
			}
		}
	}()
	for done := 0; done < len(p); {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		position := offset + int64(done)
		index := position / BlockBytes
		inBlock := int(position % BlockBytes)
		size := BlockBytes - inBlock
		if size > len(p)-done {
			size = len(p) - done
		}
		var b []byte
		if inBlock == 0 && size == BlockBytes {
			b = make([]byte, BlockBytes)
		} else {
			b, err = v.readBlock(ctx, n, index)
			if err != nil {
				return 0, err
			}
		}
		copy(b[inBlock:inBlock+size], p[done:done+size])
		id, e := randomID()
		if e != nil {
			clear(b)
			return 0, e
		}
		err = v.objects.Write("block/"+id, b)
		clear(b)
		if err != nil {
			return 0, err
		}
		created = append(created, id)
		if old := changed.Blocks[index]; old != "" {
			replaced = append(replaced, old)
		}
		changed.Blocks[index] = id
		done += size
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if err = v.commit(next); err != nil {
		return 0, err
	}
	committed = true
	for _, id := range replaced {
		_ = v.objects.Remove("block/" + id)
	}
	return len(p), nil
}
func (h *Handle) Truncate(ctx context.Context, size int64) error {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := h.node()
	if err != nil {
		return err
	}
	if size < 0 || size > MaxBytes {
		return ErrQuota
	}
	next := cloneState(v.state)
	changed := cloneNode(n)
	next.Nodes[h.id] = changed
	changed.MTime, changed.CTime = time.Now().UnixNano(), time.Now().UnixNano()
	changed.Size = size
	if size < changed.BaseSize {
		changed.BaseSize = size
	}
	if err = validateState(next); err != nil {
		return err
	}
	removed := []string{}
	for index, id := range changed.Blocks {
		if index*BlockBytes >= size {
			delete(changed.Blocks, index)
			removed = append(removed, id)
		}
	}
	newID := ""
	if size < n.Size && size%BlockBytes != 0 {
		index := size / BlockBytes
		b, e := v.readBlock(ctx, n, index)
		if e != nil {
			return e
		}
		clear(b[size%BlockBytes:])
		newID, e = randomID()
		if e != nil {
			clear(b)
			return e
		}
		err = v.objects.Write("block/"+newID, b)
		clear(b)
		if err != nil {
			return err
		}
		if old := changed.Blocks[index]; old != "" {
			removed = append(removed, old)
		}
		changed.Blocks[index] = newID
	}
	if err = v.commit(next); err != nil {
		if newID != "" {
			_ = v.objects.Remove("block/" + newID)
		}
		return err
	}
	for _, id := range removed {
		_ = v.objects.Remove("block/" + id)
	}
	return nil
}
func (h *Handle) Close() error {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	v.handles[h.id]--
	if v.closed {
		return nil
	}
	next := cloneState(v.state)
	v.reclaimUnlinked(&next)
	return v.commit(next)
}

func (h *Handle) Stat() (Entry, error) {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := h.node()
	if err != nil {
		return Entry{}, err
	}
	return nodeEntry("", h.id, n), nil
}
func (v *View) SetMeta(name string, mode *fs.FileMode, atime, mtime *int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	id, n, err := v.lookup(name)
	if err != nil {
		return err
	}
	return v.setMeta(id, n, mode, atime, mtime)
}
func (h *Handle) SetMeta(mode *fs.FileMode, atime, mtime *int64) error {
	v := h.view
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := h.node()
	if err != nil {
		return err
	}
	return v.setMeta(h.id, n, mode, atime, mtime)
}
func (v *View) setMeta(id string, n *node, mode *fs.FileMode, atime, mtime *int64) error {
	next := cloneState(v.state)
	copy := cloneNode(n)
	next.Nodes[id] = copy
	if mode != nil {
		copy.Mode = n.Mode.Type() | mode.Perm()&0700
	}
	if atime != nil {
		copy.ATime = *atime
	}
	if mtime != nil {
		copy.MTime = *mtime
	}
	copy.CTime = time.Now().UnixNano()
	return v.commit(next)
}
func (v *View) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	v.release()
	if closer, ok := v.source.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (v *View) Space() (int64, int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var used int64
	blocks := int64(0)
	for _, n := range v.state.Nodes {
		if !n.Mode.IsDir() {
			used += n.Size
		}
		blocks += int64(len(n.Blocks))
	}
	if blocks*BlockBytes > used {
		used = blocks * BlockBytes
	}
	return MaxBytes - used, MaxEntries + 1 - len(v.state.Paths)
}
