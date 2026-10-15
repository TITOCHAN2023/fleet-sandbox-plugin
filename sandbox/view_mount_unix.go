//go:build linux || darwin

package sandbox

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"path"
	"runtime"
	"syscall"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type mountedFileView struct {
	view   *overlay.View
	server *fuse.Server
	root   *fileViewNode
}

func mountFileView(sourceDir, stateDir, mountpoint string, emit Emit) (*mountedFileView, error) {
	if contains(sourceDir, stateDir) || contains(stateDir, sourceDir) || contains(sourceDir, mountpoint) || contains(mountpoint, sourceDir) {
		return nil, errors.New("file view paths cannot overlap")
	}
	source, err := newLocalViewSource(sourceDir)
	if err != nil {
		return nil, err
	}
	view, err := mountFileViewSource(source, stateDir, mountpoint, emit)
	if err != nil {
		source.Close()
	}
	return view, err
}
func mountFileViewSource(source overlay.Source, stateDir, mountpoint string, emit Emit) (*mountedFileView, error) {
	v, err := overlay.Open(context.Background(), stateDir, source, storageCipher.Load())
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(mountpoint, 0700); err != nil {
		v.Close()
		return nil, err
	}
	if files, e := os.ReadDir(mountpoint); e != nil || len(files) != 0 {
		v.Close()
		return nil, errors.New("mount directory must be empty")
	}
	if emit == nil {
		emit = func(string, string, string, map[string]any) {}
	}
	root := &fileViewNode{view: v, emit: emit}
	root.root = root
	// Fork preparation must not wait for a callback served by its only Go P.
	if runtime.GOMAXPROCS(0) < 2 {
		runtime.GOMAXPROCS(2)
	}
	server, err := fs.Mount(mountpoint, root, &fs.Options{MountOptions: fuse.MountOptions{Name: "fleet-workspace", FsName: "fleet-workspace", MaxWrite: overlay.BlockBytes, Options: []string{"default_permissions"}}})
	if err != nil {
		v.Close()
		return nil, err
	}
	if err = server.WaitMount(); err != nil {
		server.Unmount()
		v.Close()
		return nil, err
	}
	// Cache unsupported ACCESS before chdir in a subsequent fork/exec.
	_ = unix.Access(mountpoint, unix.X_OK)
	return &mountedFileView{view: v, server: server, root: root}, nil
}
func (m *mountedFileView) Close() error {
	if err := m.server.Unmount(); err != nil {
		return err
	}
	m.server.Wait()
	return m.view.Close()
}

type fileViewNode struct {
	fs.Inode
	view *overlay.View
	root *fileViewNode
	emit Emit
}
type fileViewHandle struct {
	handle *overlay.Handle
	node   *fileViewNode
	name   string
	flags  uint32
}

func (n *fileViewNode) name() string {
	p := n.Path(&n.root.Inode)
	if p == "" {
		return "."
	}
	return p
}
func (n *fileViewNode) child(name string) string { return path.Join(n.name(), name) }
func fileType(mode iofs.FileMode) uint32 {
	if mode.IsDir() {
		return syscall.S_IFDIR
	}
	return syscall.S_IFREG
}
func fileAttr(entry overlay.Entry, out *fuse.Attr) {
	out.Mode = fileType(entry.Mode) | uint32(entry.Mode.Perm())
	out.Size = uint64(entry.Size)
	out.Nlink = 1
	out.Uid = uint32(os.Getuid())
	out.Gid = uint32(os.Getgid())
	out.Blksize = 4096
	out.Blocks = (out.Size + 511) / 512
	if b, err := hex.DecodeString(entry.ID); err == nil && len(b) == 16 {
		out.Ino = binary.BigEndian.Uint64(b[:8])
	}
	setTime := func(t int64, seconds *uint64, nanos *uint32) {
		if t < 0 {
			t = 0
		}
		*seconds = uint64(t / 1e9)
		*nanos = uint32(t % 1e9)
	}
	setTime(entry.MTime, &out.Mtime, &out.Mtimensec)
	setTime(entry.ATime, &out.Atime, &out.Atimensec)
	setTime(entry.CTime, &out.Ctime, &out.Ctimensec)
}
func viewErr(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	if errors.Is(err, overlay.ErrQuota) {
		return syscall.ENOSPC
	}
	if errors.Is(err, overlay.ErrSourceChanged) {
		return syscall.EIO
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return syscall.EINTR
	}
	return fs.ToErrno(err)
}
func (n *fileViewNode) event(ctx context.Context, phase, name string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	details["path"], details["observation"] = name, "virtual_filesystem"
	if caller, ok := fuse.FromContext(ctx); ok {
		details["pid"] = caller.Pid
	}
	n.emit("file", phase, name, details)
}
func (n *fileViewNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	var entry overlay.Entry
	var err error
	if h, ok := fh.(*fileViewHandle); ok {
		entry, err = h.handle.Stat()
	} else {
		entry, err = n.view.Stat(n.name())
	}
	if err != nil {
		return viewErr(err)
	}
	fileAttr(entry, &out.Attr)
	return 0
}
func (n *fileViewNode) Access(context.Context, uint32) syscall.Errno { return syscall.ENOSYS }
func (n *fileViewNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	entry, err := n.view.Stat(n.child(name))
	if err != nil {
		return nil, viewErr(err)
	}
	fileAttr(entry, &out.Attr)
	return n.NewInode(ctx, &fileViewNode{view: n.view, root: n.root, emit: n.emit}, fs.StableAttr{Mode: fileType(entry.Mode), Ino: out.Ino}), 0
}
func (n *fileViewNode) Readdir(context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := n.view.ReadDir(n.name())
	if err != nil {
		return nil, viewErr(err)
	}
	list := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		attr := fuse.Attr{}
		fileAttr(entry, &attr)
		list = append(list, fuse.DirEntry{Name: path.Base(entry.Path), Mode: fileType(entry.Mode), Ino: attr.Ino})
	}
	return fs.NewListDirStream(list), 0
}
func (n *fileViewNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	name := n.name()
	h, err := n.view.OpenFile(name)
	if err != nil {
		return nil, 0, viewErr(err)
	}
	if flags&syscall.O_TRUNC != 0 {
		if err = h.Truncate(ctx, 0); err != nil {
			h.Close()
			return nil, 0, viewErr(err)
		}
	}
	n.event(ctx, "opened", name, map[string]any{"flags": flags})
	return &fileViewHandle{handle: h, node: n, name: name, flags: flags}, 0, 0
}
func (n *fileViewNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	full := n.child(name)
	if err := n.view.Create(full, iofs.FileMode(mode)); err != nil {
		return nil, nil, 0, viewErr(err)
	}
	inode, errno := n.Lookup(ctx, name, out)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	h, err := n.view.OpenFile(full)
	if err != nil {
		return nil, nil, 0, viewErr(err)
	}
	n.event(ctx, "created", full, nil)
	return inode, &fileViewHandle{handle: h, node: n, name: full, flags: flags}, 0, 0
}
func (n *fileViewNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	full := n.child(name)
	if err := n.view.Mkdir(full, iofs.FileMode(mode)); err != nil {
		return nil, viewErr(err)
	}
	n.event(ctx, "created", full, map[string]any{"directory": true})
	return n.Lookup(ctx, name, out)
}
func (n *fileViewNode) Unlink(ctx context.Context, name string) syscall.Errno {
	full := n.child(name)
	entry, err := n.view.Stat(full)
	if err != nil {
		return viewErr(err)
	}
	if entry.Mode.IsDir() {
		return syscall.EISDIR
	}
	if err = n.view.Remove(full); err != nil {
		return viewErr(err)
	}
	n.event(ctx, "deleted", full, nil)
	return 0
}
func (n *fileViewNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	full := n.child(name)
	entry, err := n.view.Stat(full)
	if err != nil {
		return viewErr(err)
	}
	if !entry.Mode.IsDir() {
		return syscall.ENOTDIR
	}
	if err = n.view.Remove(full); err != nil {
		return viewErr(err)
	}
	n.event(ctx, "deleted", full, map[string]any{"directory": true})
	return 0
}
func (n *fileViewNode) Rename(ctx context.Context, name string, parent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if flags != 0 {
		return syscall.ENOTSUP
	}
	target, ok := parent.(*fileViewNode)
	if !ok || target.view != n.view {
		return syscall.EXDEV
	}
	old, newPath := n.child(name), target.child(newName)
	if err := n.view.Rename(old, newPath); err != nil {
		return viewErr(err)
	}
	n.event(ctx, "renamed", old, map[string]any{"destination": newPath})
	return 0
}
func (n *fileViewNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if uid, ok := in.GetUID(); ok && uid != uint32(os.Getuid()) {
		return syscall.EPERM
	}
	if gid, ok := in.GetGID(); ok && gid != uint32(os.Getgid()) {
		return syscall.EPERM
	}
	h, ok := fh.(*fileViewHandle)
	if !ok {
		entry, err := n.view.Stat(n.name())
		if err != nil {
			return viewErr(err)
		}
		if entry.Mode.IsDir() {
			if _, ok := in.GetSize(); ok {
				return syscall.EISDIR
			}
			mode, atime, mtime := viewSetMeta(in)
			if err = n.view.SetMeta(n.name(), mode, atime, mtime); err != nil {
				return viewErr(err)
			}
			return n.Getattr(ctx, nil, out)
		}
		handle, err := n.view.OpenFile(n.name())
		if err != nil {
			return viewErr(err)
		}
		defer handle.Close()
		h = &fileViewHandle{handle: handle, node: n, name: n.name()}
	}
	return h.Setattr(ctx, in, out)
}
func (n *fileViewNode) Statfs(_ context.Context, out *fuse.StatfsOut) syscall.Errno {
	free, entries := n.view.Space()
	out.Bsize = 4096
	out.Frsize = 4096
	out.Blocks = uint64(overlay.MaxBytes / 4096)
	out.Bfree = uint64(free / 4096)
	out.Bavail = out.Bfree
	out.Files = overlay.MaxEntries
	out.Ffree = uint64(entries)
	out.NameLen = 255
	return 0
}
func (h *fileViewHandle) Read(ctx context.Context, b []byte, offset int64) (fuse.ReadResult, syscall.Errno) {
	n, err := h.handle.ReadAt(ctx, b, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		h.node.event(ctx, "failed", h.name, map[string]any{"error": err.Error()})
		return nil, viewErr(err)
	}
	h.node.event(ctx, "read", h.name, map[string]any{"offset": offset, "bytes": n})
	return fuse.ReadResultData(b[:n]), 0
}
func (h *fileViewHandle) Write(ctx context.Context, b []byte, offset int64) (uint32, syscall.Errno) {
	if h.flags&syscall.O_ACCMODE == syscall.O_RDONLY {
		return 0, syscall.EBADF
	}
	var n int
	var err error
	if h.flags&syscall.O_APPEND != 0 {
		n, err = h.handle.Append(ctx, b)
	} else {
		n, err = h.handle.WriteAt(ctx, b, offset)
	}
	if err != nil {
		return 0, viewErr(err)
	}
	h.node.event(ctx, "written", h.name, map[string]any{"offset": offset, "bytes": n})
	return uint32(n), 0
}
func (h *fileViewHandle) Release(context.Context) syscall.Errno       { return viewErr(h.handle.Close()) }
func (h *fileViewHandle) Flush(context.Context) syscall.Errno         { return 0 }
func (h *fileViewHandle) Fsync(context.Context, uint32) syscall.Errno { return 0 }
func (h *fileViewHandle) Getattr(_ context.Context, out *fuse.AttrOut) syscall.Errno {
	entry, err := h.handle.Stat()
	if err != nil {
		return viewErr(err)
	}
	fileAttr(entry, &out.Attr)
	return 0
}
func (h *fileViewHandle) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if uid, ok := in.GetUID(); ok && uid != uint32(os.Getuid()) {
		return syscall.EPERM
	}
	if gid, ok := in.GetGID(); ok && gid != uint32(os.Getgid()) {
		return syscall.EPERM
	}
	if size, ok := in.GetSize(); ok {
		if size > uint64(overlay.MaxBytes) {
			return syscall.ENOSPC
		}
		if err := h.handle.Truncate(ctx, int64(size)); err != nil {
			return viewErr(err)
		}
		h.node.event(ctx, "truncated", h.name, map[string]any{"size": size})
	}
	mode, atime, mtime := viewSetMeta(in)
	if mode != nil || atime != nil || mtime != nil {
		if err := h.handle.SetMeta(mode, atime, mtime); err != nil {
			return viewErr(err)
		}
	}
	return h.Getattr(ctx, out)
}
func viewSetMeta(in *fuse.SetAttrIn) (mode *iofs.FileMode, atime, mtime *int64) {
	if value, ok := in.GetMode(); ok {
		v := iofs.FileMode(value)
		mode = &v
	}
	if value, ok := in.GetATime(); ok {
		v := value.UnixNano()
		atime = &v
	}
	if value, ok := in.GetMTime(); ok {
		v := value.UnixNano()
		mtime = &v
	}
	return mode, atime, mtime
}
