//go:build linux

package sandbox

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox/overlay"
	"golang.org/x/sys/unix"
)

// Drain kernel events synchronously; metadata can miss a write within one tick.
type localSourceGuard struct {
	mu     sync.Mutex
	fd     int
	nonce  string
	names  map[int]string
	epochs map[string]uint64
	broken bool
}

func newLocalSourceGuard() (*localSourceGuard, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &localSourceGuard{fd: fd, nonce: hex.EncodeToString(b[:]), names: map[int]string{}, epochs: map[string]uint64{}}, nil
}
func (g *localSourceGuard) Watch(name string, f *os.File) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fd < 0 {
		return os.ErrClosed
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return err
	}
	if !supportsLocalSourceEvents(fs.Type) {
		return errors.New("demand source requires a supported local filesystem; remote and stacked sources need their own version guard")
	}
	wd, err := unix.InotifyAddWatch(g.fd, "/proc/self/fd/"+strconv.FormatUint(uint64(f.Fd()), 10), unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF|unix.IN_CLOSE_WRITE)
	if err != nil {
		return err
	}
	g.names[wd] = name
	return nil
}

func supportsLocalSourceEvents(kind int64) bool {
	switch kind {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC:
		return true
	default:
		return false
	}
}
func (g *localSourceGuard) Stamp(name string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fd < 0 {
		return "", os.ErrClosed
	}
	var buffer [64 << 10]byte
	for {
		n, err := unix.Read(g.fd, buffer[:])
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			break
		}
		for offset := 0; offset < n; {
			if n-offset < unix.SizeofInotifyEvent {
				g.broken = true
				break
			}
			event := buffer[offset:]
			wd := int(int32(binary.NativeEndian.Uint32(event)))
			mask := binary.NativeEndian.Uint32(event[4:])
			length := int(binary.NativeEndian.Uint32(event[12:]))
			if length > n-offset-unix.SizeofInotifyEvent {
				g.broken = true
				break
			}
			if mask&unix.IN_Q_OVERFLOW != 0 {
				g.broken = true
			}
			if file := g.names[wd]; file != "" {
				g.epochs[file]++
			}
			offset += unix.SizeofInotifyEvent + length
		}
	}
	if g.broken {
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
	return err
}
