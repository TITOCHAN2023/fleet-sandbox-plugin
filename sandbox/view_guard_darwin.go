//go:build darwin

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"golang.org/x/sys/unix"
)

// Retain the opened inode, not a path which may be replaced. Events are drained
// before and after reads; no goroutine scheduling delay enters the version check.
type localSourceGuard struct {
	mu     sync.Mutex
	fd     int
	nonce  string
	files  map[string]*os.File
	names  map[uint64]string
	epochs map[string]uint64
	broken bool
}

func newLocalSourceGuard() (*localSourceGuard, error) {
	fd, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &localSourceGuard{fd: fd, nonce: hex.EncodeToString(b[:]), files: map[string]*os.File{}, names: map[uint64]string{}, epochs: map[string]uint64{}}, nil
}

func (g *localSourceGuard) Watch(name string, f *os.File) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.drain(); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return err
	}
	var kind strings.Builder
	for _, c := range fs.Fstypename {
		if c == 0 {
			break
		}
		kind.WriteByte(byte(c))
	}
	if kind.String() != "apfs" && kind.String() != "hfs" {
		return errors.New("demand source requires APFS or HFS; remote filesystems need their own version guard")
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
		delete(g.names, uint64(old.Fd()))
		old.Close()
		delete(g.files, name)
		g.epochs[name]++
	}
	if len(g.files) >= overlay.MaxEntries {
		return overlay.ErrQuota
	}
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	change := unix.Kevent_t{}
	unix.SetKevent(&change, fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR)
	change.Fflags = unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_ATTRIB | unix.NOTE_LINK | unix.NOTE_RENAME | unix.NOTE_DELETE | unix.NOTE_REVOKE
	if _, err = unix.Kevent(g.fd, []unix.Kevent_t{change}, nil, nil); err != nil {
		unix.Close(fd)
		return err
	}
	g.files[name] = os.NewFile(uintptr(fd), name)
	g.names[uint64(fd)] = name
	return nil
}

func (g *localSourceGuard) drain() error {
	if g.fd < 0 {
		return os.ErrClosed
	}
	if g.broken {
		return overlay.ErrSourceChanged
	}
	var events [64]unix.Kevent_t
	for {
		zero := unix.Timespec{}
		n, err := unix.Kevent(g.fd, nil, events[:], &zero)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			g.broken = true
			return err
		}
		if n == 0 {
			return nil
		}
		for _, event := range events[:n] {
			name, found := g.names[event.Ident]
			if !found || event.Flags&unix.EV_ERROR != 0 || event.Filter != unix.EVFILT_VNODE {
				g.broken = true
				return overlay.ErrSourceChanged
			}
			g.epochs[name]++
		}
	}
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
	if g.fd < 0 {
		return nil
	}
	err := unix.Close(g.fd)
	g.fd = -1
	for name, f := range g.files {
		err = errors.Join(err, f.Close())
		delete(g.files, name)
	}
	return err
}
