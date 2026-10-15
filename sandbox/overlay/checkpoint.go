package overlay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"sort"
)

// Checkpoint persists all still-needed lower data while its version guard is
// alive. Missing data stays an explicit gap; callers must never replace it with
// the current contents of a changed source after a restart.
func (v *View) Checkpoint(ctx context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, fs.ErrClosed
	}
	gaps := []string{}
	for name, id := range v.state.Paths {
		n := v.state.Nodes[id]
		if n.Mode.IsDir() {
			continue
		}
		if err := v.checkpointNode(ctx, id, n); err != nil {
			if ctx.Err() != nil {
				return gaps, ctx.Err()
			}
			gaps = append(gaps, name)
		}
	}
	next := cloneState(v.state)
	for name, entry := range v.state.Initial {
		if !entry.Mode.IsRegular() || v.state.Before[name] != "" {
			continue
		}
		hash, err := v.sourceHash(ctx, entry)
		if err != nil {
			if ctx.Err() != nil {
				return gaps, ctx.Err()
			}
			gaps = append(gaps, "source:"+name)
			continue
		}
		next.Before[name] = hash
	}
	if err := v.commit(next); err != nil {
		return gaps, err
	}
	sort.Strings(gaps)
	return gaps, nil
}
func (v *View) checkpointNode(ctx context.Context, id string, n *node) error {
	next := cloneState(v.state)
	copy := cloneNode(n)
	next.Nodes[id] = copy
	created := []string{}
	committed := false
	defer func() {
		if !committed {
			for _, id := range created {
				_ = v.objects.Remove("block/" + id)
			}
		}
	}()
	for index := int64(0); index*BlockBytes < n.Size; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n.Blocks[index] != "" {
			continue
		}
		b, err := v.readBlock(ctx, n, index)
		if err != nil {
			return err
		}
		blockID, err := randomID()
		if err != nil {
			clear(b)
			return err
		}
		copy.Blocks[index] = blockID
		if err = validateState(next); err != nil {
			clear(b)
			return err
		}
		err = v.objects.Write("block/"+blockID, b)
		clear(b)
		if err != nil {
			return err
		}
		created = append(created, blockID)
	}
	if err := v.commit(next); err != nil {
		return err
	}
	committed = true
	return nil
}
func (v *View) sourceHash(ctx context.Context, entry Entry) (string, error) {
	h := sha256.New()
	buffer := make([]byte, BlockBytes)
	defer clear(buffer)
	for offset := int64(0); offset < entry.Size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		count := int64(len(buffer))
		if count > entry.Size-offset {
			count = entry.Size - offset
		}
		n, err := v.source.ReadAt(ctx, entry.Path, entry.Version, buffer[:count], offset)
		if err != nil && err != io.EOF {
			return "", err
		}
		if int64(n) != count {
			return "", io.ErrUnexpectedEOF
		}
		h.Write(buffer[:n])
		offset += int64(n)
	}
	// Empty files also require a live version check.
	if entry.Size == 0 {
		if _, err := v.source.ReadAt(ctx, entry.Path, entry.Version, nil, 0); err != nil && err != io.EOF {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (v *View) BeforeHashes() map[string]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]string, len(v.state.Before))
	for k, b := range v.state.Before {
		out[k] = b
	}
	return out
}
func (v *View) InitialEntries() []Entry {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Entry, 0, len(v.state.Initial))
	for _, e := range v.state.Initial {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
