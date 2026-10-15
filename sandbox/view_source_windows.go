//go:build windows

package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func viewFileVersion(f *os.File) (string, error) {
	var id windows.ByHandleFileInformation
	handle := windows.Handle(f.Fd())
	if err := windows.GetFileInformationByHandle(handle, &id); err != nil {
		return "", err
	}
	basic := struct {
		Created, Accessed, Written, Changed int64
		Attributes                          uint32
		Padding                             uint32
	}{}
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return "", err
	}
	b := fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d/%d/%d", id.VolumeSerialNumber, id.FileIndexHigh, id.FileIndexLow, id.NumberOfLinks, id.FileSizeHigh, id.FileSizeLow, basic.Written, basic.Changed, basic.Attributes)
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:]), nil
}
