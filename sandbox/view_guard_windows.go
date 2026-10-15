//go:build windows

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"golang.org/x/sys/windows"
)

const windowsNotifyMask = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
	windows.FILE_NOTIFY_CHANGE_DIR_NAME |
	windows.FILE_NOTIFY_CHANGE_ATTRIBUTES |
	windows.FILE_NOTIFY_CHANGE_SIZE |
	windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
	windows.FILE_NOTIFY_CHANGE_CREATION |
	windows.FILE_NOTIFY_CHANGE_SECURITY

// One ReadDirectoryChanges call is outstanding per directory. Completion is
// reissued on the other buffer before the completed buffer is parsed. Overflow
// fails the guard. A sibling filename does not move a watched epoch.
type localSourceGuard struct {
	mu      sync.Mutex
	port    windows.Handle
	nonce   string
	nextKey uintptr
	dirs    map[string]*dirWatch
	byKey   map[uintptr]*dirWatch
	files   map[string]*os.File
	epochs  map[string]uint64
	closed  bool
	broken  bool
}

type notifySlot struct {
	buf [64 << 10]byte
	ov  windows.Overlapped
}

type dirWatch struct {
	handle  windows.Handle
	key     uintptr
	slots   [2]notifySlot
	pending int
	next    int
	names   map[string]string
}

func newLocalSourceGuard() (*localSourceGuard, error) {
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, err
	}
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		windows.CloseHandle(port)
		return nil, err
	}
	return &localSourceGuard{
		port: port, nonce: hex.EncodeToString(b[:]),
		dirs: map[string]*dirWatch{}, byKey: map[uintptr]*dirWatch{},
		files: map[string]*os.File{}, epochs: map[string]uint64{},
	}, nil
}

func (g *localSourceGuard) Watch(name string, f *os.File) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.drain(); err != nil {
		return err
	}
	if old := g.files[name]; old != nil {
		before, err := old.Stat()
		if err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil {
			return err
		}
		if os.SameFile(before, after) {
			return nil
		}
		g.dropLocked(name)
		g.epochs[name]++
	}
	if len(g.files) >= overlay.MaxEntries {
		return overlay.ErrQuota
	}
	handle := windows.Handle(f.Fd())
	if err := localNotifyVolume(handle); err != nil {
		return err
	}
	dir, err := parentPath(handle)
	if err != nil {
		return err
	}
	watch, err := g.directoryLocked(dir)
	if err != nil {
		return err
	}
	kept, err := duplicateFile(handle, name)
	if err != nil {
		return err
	}
	base := notifyBase(slashBase(name))
	watch.names[base] = name
	if err = watch.issue(); err != nil {
		delete(watch.names, base)
		kept.Close()
		return err
	}
	g.files[name] = kept
	return nil
}

func (g *localSourceGuard) Stamp(name string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.drain(); err != nil {
		return "", err
	}
	if g.files[name] == nil {
		return "", overlay.ErrSourceChanged
	}
	return fmt.Sprintf("/%s/%d", g.nonce, g.epochs[name]), nil
}

func (g *localSourceGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	var err error
	for _, dir := range g.dirs {
		err = errors.Join(err, windows.CancelIoEx(dir.handle, nil))
	}
	for i := 0; i < len(g.dirs)+1; i++ {
		var qty uint32
		var key uintptr
		var ov *windows.Overlapped
		waitErr := windows.GetQueuedCompletionStatus(g.port, &qty, &key, &ov, 0)
		if errors.Is(waitErr, windows.WAIT_TIMEOUT) {
			break
		}
	}
	for path, dir := range g.dirs {
		err = errors.Join(err, windows.CloseHandle(dir.handle))
		delete(g.dirs, path)
		delete(g.byKey, dir.key)
	}
	for name, f := range g.files {
		err = errors.Join(err, f.Close())
		delete(g.files, name)
	}
	err = errors.Join(err, windows.CloseHandle(g.port))
	g.port = 0
	return err
}

func (g *localSourceGuard) drain() error {
	if g.closed {
		return os.ErrClosed
	}
	if g.broken {
		return overlay.ErrSourceChanged
	}
	for {
		dir, slot, qty, err := g.poll()
		if errors.Is(err, windows.WAIT_TIMEOUT) {
			return nil
		}
		if consumeErr := g.consume(dir, slot, qty, err); consumeErr != nil {
			return consumeErr
		}
	}
}

func (g *localSourceGuard) poll() (*dirWatch, int, uint32, error) {
	var qty uint32
	var key uintptr
	var ov *windows.Overlapped
	err := windows.GetQueuedCompletionStatus(g.port, &qty, &key, &ov, 0)
	dir := g.byKey[key]
	slot := -1
	if dir != nil && ov != nil {
		slot = dir.slotOf(ov)
	}
	return dir, slot, qty, err
}

func (g *localSourceGuard) consume(dir *dirWatch, slot int, qty uint32, err error) error {
	if dir == nil || slot < 0 || dir.pending != slot {
		g.broken = true
		return overlay.ErrSourceChanged
	}
	dir.pending = -1
	if errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR) || int(qty) > len(dir.slots[slot].buf) {
		g.broken = true
		return overlay.ErrSourceChanged
	}
	if err != nil {
		g.broken = true
		return err
	}
	if err = dir.issue(); err != nil {
		g.broken = true
		return err
	}
	names, err := parseNotifyNames(dir.slots[slot].buf[:qty])
	if err != nil {
		g.broken = true
		return overlay.ErrSourceChanged
	}
	for _, name := range names {
		if full := dir.names[notifyBase(name)]; full != "" {
			g.epochs[full]++
		}
	}
	return nil
}

func (g *localSourceGuard) directoryLocked(path string) (*dirWatch, error) {
	if dir := g.dirs[path]; dir != nil {
		return dir, nil
	}
	if len(g.dirs) >= overlay.MaxEntries {
		return nil, overlay.ErrQuota
	}
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pathp, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	g.nextKey++
	dir := &dirWatch{handle: handle, key: g.nextKey, pending: -1, names: map[string]string{}}
	if _, err = windows.CreateIoCompletionPort(handle, g.port, dir.key, 0); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	g.dirs[path] = dir
	g.byKey[dir.key] = dir
	return dir, nil
}

func (g *localSourceGuard) dropLocked(name string) {
	if f := g.files[name]; f != nil {
		f.Close()
		delete(g.files, name)
	}
	base := notifyBase(slashBase(name))
	for _, dir := range g.dirs {
		if dir.names[base] == name {
			delete(dir.names, base)
		}
	}
}

func (d *dirWatch) issue() error {
	if d.pending >= 0 {
		return nil
	}
	i := d.next
	d.slots[i].ov = windows.Overlapped{}
	err := windows.ReadDirectoryChanges(d.handle, &d.slots[i].buf[0], uint32(len(d.slots[i].buf)), false, windowsNotifyMask, nil, &d.slots[i].ov, 0)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return err
	}
	d.pending = i
	d.next ^= 1
	return nil
}

func (d *dirWatch) slotOf(ov *windows.Overlapped) int {
	for i := range d.slots {
		if ov == &d.slots[i].ov {
			return i
		}
	}
	return -1
}

func localNotifyVolume(file windows.Handle) error {
	var probe [8]byte
	err := windows.GetFileInformationByHandleEx(file, windows.FileRemoteProtocolInfo, &probe[0], uint32(len(probe)))
	if err == nil || errors.Is(err, windows.ERROR_MORE_DATA) || errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return errors.New("demand source requires a local volume; remote filesystems need their own version guard")
	}
	if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) && !errors.Is(err, windows.ERROR_INVALID_FUNCTION) && !errors.Is(err, windows.ERROR_INVALID_LEVEL) && !errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		return err
	}
	var kind [32]uint16
	if err = windows.GetVolumeInformationByHandle(file, nil, 0, nil, nil, nil, &kind[0], uint32(len(kind))); err != nil {
		return err
	}
	name := windows.UTF16ToString(kind[:])
	if name != "NTFS" && name != "ReFS" {
		return errors.New("demand source requires NTFS or ReFS; other volumes need their own version guard")
	}
	return nil
}

func parentPath(file windows.Handle) (string, error) {
	buf := make([]uint16, 1024)
	n, err := windows.GetFinalPathNameByHandle(file, &buf[0], uint32(len(buf)), 0)
	if err == nil && n >= uint32(len(buf)) {
		buf = make([]uint16, n+1)
		n, err = windows.GetFinalPathNameByHandle(file, &buf[0], uint32(len(buf)), 0)
	}
	if err != nil {
		return "", err
	}
	full := windows.UTF16ToString(buf[:n])
	dir := filepath.Dir(full)
	root := volumeRoot(full)
	rootp, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", err
	}
	switch windows.GetDriveType(rootp) {
	case windows.DRIVE_FIXED, windows.DRIVE_RAMDISK:
		return dir, nil
	default:
		return "", errors.New("demand source requires a fixed local volume; remote filesystems need their own version guard")
	}
}

func volumeRoot(path string) string {
	trimmed := strings.TrimPrefix(path, `\\?\UNC\`)
	trimmed = strings.TrimPrefix(trimmed, `\\?\`)
	vol := filepath.VolumeName(trimmed)
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\?\UNC\` + vol + `\`
	}
	if strings.HasPrefix(path, `\\?\`) {
		return `\\?\` + vol + `\`
	}
	return vol + `\`
}

func duplicateFile(handle windows.Handle, name string) (*os.File, error) {
	var dup windows.Handle
	err := windows.DuplicateHandle(windows.CurrentProcess(), handle, windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(dup), name), nil
}

func slashBase(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func notifyBase(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}
