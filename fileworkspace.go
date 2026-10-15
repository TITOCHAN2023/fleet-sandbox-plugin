package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox"
	"os"
)

func runFileWorkspaceStdio(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 96<<10)
	lines := make(chan []byte, 1)
	go func() {
		defer close(lines)
		defer cancel() // Parent stdin closes on cancellation/death, including macOS.
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	session := sandbox.FileWorkspaceSession{Context: ctx}
	defer session.Close()
	emit, status := sandbox.ActivityEmitter()
	nonce := ""
	initialized := false
	encoder := json.NewEncoder(os.Stdout)
	for {
		var line []byte
		select {
		case <-ctx.Done():
			return
		case data, ok := <-lines:
			if !ok {
				return
			}
			line = data
		}
		var req sandbox.FileWorkspaceRequest
		err := json.Unmarshal(line, &req)
		secret, decodeErr := hex.DecodeString(req.Nonce)
		if err != nil || req.V != 1 || decodeErr != nil || len(secret) != 32 || (nonce != "" && req.Nonce != nonce) {
			return
		}
		if nonce == "" {
			if req.Action != "hello" {
				return
			}
			nonce = req.Nonce
		}
		if !initialized {
			err = sandbox.InitStorage(ctx)
			initialized = err == nil
		}
		var result any
		if err == nil {
			result, err = session.Handle(req, emit)
		}
		if auditErr := status(); err == nil && auditErr != nil {
			err = auditErr
		}
		reply := map[string]any{"v": 1, "nonce": nonce, "ok": err == nil}
		if err != nil {
			reply["error"] = err.Error()
		} else {
			reply["result"] = result
		}
		if encoder.Encode(reply) != nil || err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
	// Clean EOF releases the workspace lock; data stays persisted.
}
