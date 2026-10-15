//go:build linux

package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
)

func viewFileVersion(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	s := info.Sys().(*syscall.Stat_t)
	b := fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d/%d/%d", s.Dev, s.Ino, s.Nlink, s.Ctim.Sec, s.Ctim.Nsec, info.Size(), info.ModTime().UnixNano(), info.Mode(), s.Uid)
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:]), nil
}
