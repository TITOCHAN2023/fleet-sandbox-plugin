package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestStreamHeaderNeverConsumesTaskProtocolBytes(t *testing.T) {
	nonce := strings.Repeat("ab", 32)
	protocol := `{"jsonrpc":"2.0","method":"initialize"}` + "\n"
	input := bytes.NewBufferString(`{"v":1,"nonce":"` + nonce + `","config":{"root":"/fixture"},"input":{"command":"/bin/cat"}}` + "\n" + protocol)
	got, err := readStreamHeader(input)
	if err != nil || got.Nonce != nonce {
		t.Fatalf("header: %#v %v", got, err)
	}
	rest, err := io.ReadAll(input)
	if err != nil || string(rest) != protocol {
		t.Fatal("bootstrap consumed task input")
	}
}

func TestStreamHeaderRejectsUnboundedOrUnauthenticatedControl(t *testing.T) {
	for _, input := range []string{`{"v":1,"nonce":"short"}` + "\n", `{"v":2,"nonce":"` + strings.Repeat("ab", 32) + `"}` + "\n", strings.Repeat("x", (64<<10)+1) + "\n", "{} {}\n", "{}"} {
		if _, err := readStreamHeader(strings.NewReader(input)); err == nil {
			t.Fatal("invalid control accepted")
		}
	}
}
