package sandbox

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func notifyRecord(name string, next uint32) []byte {
	chars := utf16.Encode([]rune(name))
	size := len(chars) * 2
	buf := make([]byte, 12+size)
	if next != 0 {
		pad := (4 - len(buf)%4) % 4
		buf = append(buf, make([]byte, pad)...)
		next = uint32(len(buf))
	}
	binary.LittleEndian.PutUint32(buf[0:], next)
	binary.LittleEndian.PutUint32(buf[4:], 3)
	binary.LittleEndian.PutUint32(buf[8:], uint32(size))
	for i, c := range chars {
		binary.LittleEndian.PutUint16(buf[12+2*i:], c)
	}
	return buf
}

func TestParseNotifyNamesReadsEveryRecord(t *testing.T) {
	buf := append(notifyRecord("a.txt", 1), notifyRecord("dir\\b", 0)...)
	names, err := parseNotifyNames(buf)
	if err != nil || len(names) != 2 || names[0] != "a.txt" || names[1] != `dir\b` {
		t.Fatalf("names %#v err %v", names, err)
	}
	if _, err = parseNotifyNames(buf[:10]); err == nil {
		t.Fatal("truncated header accepted")
	}
	odd := notifyRecord("a", 0)
	binary.LittleEndian.PutUint32(odd[8:], 1)
	if _, err = parseNotifyNames(odd); err == nil {
		t.Fatal("odd filename length accepted")
	}
	if names, err = parseNotifyNames(nil); err != nil || names != nil {
		t.Fatal("empty buffer", names, err)
	}
}
