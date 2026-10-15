package sandbox

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

var errNotifyBuffer = errors.New("directory notification buffer is malformed")

// parseNotifyNames reads one ReadDirectoryChangesW buffer. Names stay as the
// kernel wrote them; the caller decides which basename it owns.
func parseNotifyNames(buf []byte) ([]string, error) {
	var names []string
	for offset := 0; offset < len(buf); {
		if len(buf)-offset < 12 {
			return nil, errNotifyBuffer
		}
		next := int(binary.LittleEndian.Uint32(buf[offset:]))
		size := int(binary.LittleEndian.Uint32(buf[offset+8:]))
		if size%2 != 0 || size > len(buf)-offset-12 {
			return nil, errNotifyBuffer
		}
		if next != 0 && (next < 12+size || next > len(buf)-offset || next%4 != 0) {
			return nil, errNotifyBuffer
		}
		chars := make([]uint16, size/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(buf[offset+12+2*i:])
		}
		names = append(names, string(utf16.Decode(chars)))
		if next == 0 {
			break
		}
		offset += next
	}
	return names, nil
}
