package overlay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
)

// Hashes reads through the view without creating plaintext temporary files.
func (v *View) Hashes(ctx context.Context) (map[string]string, []string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	gaps := []string{}
	for name, id := range v.state.Paths {
		n := v.state.Nodes[id]
		if n.Mode.IsDir() {
			continue
		}
		hash, err := v.nodeHash(ctx, n)
		if err != nil {
			if errors.Is(err, ErrSourceChanged) {
				gaps = append(gaps, name)
				continue
			}
			return nil, gaps, err
		}
		out[name] = hash
	}
	sort.Strings(gaps)
	return out, gaps, nil
}
func (v *View) nodeHash(ctx context.Context, n *node) (string, error) {
	h := sha256.New()
	for index := int64(0); index*BlockBytes < n.Size; index++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		b, err := v.readBlock(ctx, n, index)
		if err != nil {
			return "", err
		}
		count := int64(len(b))
		if count > n.Size-index*BlockBytes {
			count = n.Size - index*BlockBytes
		}
		h.Write(b[:count])
		clear(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
