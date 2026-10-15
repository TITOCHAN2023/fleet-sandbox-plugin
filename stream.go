package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/sandbox"
)

type streamRequest struct {
	V      int              `json:"v"`
	Nonce  string           `json:"nonce"`
	Config sandbox.Config   `json:"config"`
	Input  sandbox.RunInput `json:"input"`
}

// Read exactly one header without buffering protocol bytes intended for the
// program. The remaining native stdin handle is inherited directly on all OSes.
func readStreamHeader(r io.Reader) (streamRequest, error) {
	var req streamRequest
	b := make([]byte, 0, 1024)
	var one [1]byte
	for len(b) <= 64<<10 {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return req, err
		}
		if one[0] == '\n' {
			if json.Unmarshal(b, &req) != nil {
				return req, errors.New("invalid native stream header")
			}
			secret, err := hex.DecodeString(req.Nonce)
			if req.V != 1 || err != nil || len(secret) != 32 {
				return req, errors.New("native stream requires version 1 and a 32-byte nonce")
			}
			return req, nil
		}
		b = append(b, one[0])
	}
	return req, errors.New("native stream header exceeds 64 KiB")
}

func runStdio(ctx context.Context) {
	req, err := readStreamHeader(os.Stdin)
	if err != nil {
		reply(nil, err)
		return
	}
	footer := func(result any, err error) {
		msg := map[string]any{"type": "fleet.native.result", "v": 1, "nonce": req.Nonce, "ok": err == nil}
		if err != nil {
			msg["error"] = err.Error()
		} else {
			msg["result"] = streamResult(result)
		}
		// Separate the broker footer even if the program's final output lacks LF.
		_, _ = os.Stdout.Write([]byte{'\n'})
		_ = json.NewEncoder(os.Stdout).Encode(msg)
	}
	if err = sandbox.InitStorage(ctx); err != nil {
		footer(nil, err)
		return
	}
	emit, status := sandbox.ActivityEmitter()
	ready := func(id, cwd string) error {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "fleet.native.ready", "v": 1, "nonce": req.Nonce, "sandbox_id": id, "cwd": cwd})
	}
	result, err := sandbox.RunStreams(ctx, req.Config, req.Input, sandbox.Streams{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}, ready, emit)
	if e := status(); e != nil && err == nil {
		err = e
	}
	footer(result, err)
}

func streamResult(value any) any {
	r, ok := value.(sandbox.Result)
	if !ok {
		return value
	}
	gaps := r.RecoveryGaps
	if len(gaps) > 128 {
		gaps = gaps[:128]
	}
	return map[string]any{"sandbox_id": r.ID, "state": r.State, "ok": r.OK, "exit_code": r.ExitCode, "coverage": r.Coverage, "encrypted_persistence": r.Encrypted, "view_mode": r.ViewMode, "changes_count": len(r.Changes), "recovery_gaps": gaps, "recovery_gap_count": len(r.RecoveryGaps)}
}
