package overlay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/TITOCHAN2023/fleet-sandbox-plugin/vault"
)

type offlineSource struct{ identity string }

func (s offlineSource) Identity() (string, error) { return s.identity, nil }
func (offlineSource) Snapshot(context.Context) ([]Entry, error) {
	return nil, errors.New("offline source cannot create a view")
}
func (offlineSource) ReadAt(context.Context, string, string, []byte, int64) (int, error) {
	return 0, ErrSourceChanged
}

// Recovery never consults the current source. Only committed blocks belonging
// to this authenticated index may be returned after the source session ends.
func OpenOffline(ctx context.Context, dir string, cipher *vault.Cipher) (*View, error) {
	objects, err := vault.OpenObjects(dir, cipher)
	if err != nil {
		return nil, err
	}
	b, err := objects.Read("index")
	if err != nil {
		return nil, err
	}
	var s state
	if json.Unmarshal(b, &s) != nil {
		return nil, errors.New("invalid view recovery index")
	}
	if err = validateState(s); err != nil {
		return nil, err
	}
	return Open(ctx, dir, offlineSource{s.Source}, cipher)
}

// Materialize exports regular files into a new, private directory. Files with
// unavailable blocks are omitted and reported; partial data is never published
// as a complete file.
func (v *View) Materialize(ctx context.Context, target string) ([]string, error) {
	if err := os.Mkdir(target, 0700); err != nil {
		return nil, err
	}
	v.mu.Lock()
	entries := make([]Entry, 0, len(v.state.Paths))
	for name, id := range v.state.Paths {
		if name != "." {
			entries = append(entries, nodeEntry(name, id, v.state.Nodes[id]))
		}
	}
	v.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	gaps := []string{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return gaps, err
		}
		if _, err := cleanName(entry.Path); err != nil {
			return gaps, err
		}
		full := filepath.Join(target, filepath.FromSlash(entry.Path))
		if entry.Mode.IsDir() {
			if err := os.MkdirAll(full, 0700); err != nil {
				return gaps, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Join(target, filepath.FromSlash(path.Dir(entry.Path))), 0700); err != nil {
			return gaps, err
		}
		err := v.materializeFile(ctx, entry, full)
		if err != nil {
			if ctx.Err() != nil {
				return gaps, ctx.Err()
			}
			if !errors.Is(err, ErrSourceChanged) {
				return gaps, err
			}
			gaps = append(gaps, entry.Path)
		}
	}
	return gaps, nil
}
func (v *View) materializeFile(ctx context.Context, entry Entry, target string) error {
	h, err := v.OpenFile(entry.Path)
	if err != nil {
		return err
	}
	defer h.Close()
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			os.Remove(target)
		}
	}()
	buffer := make([]byte, BlockBytes)
	defer clear(buffer)
	for offset := int64(0); offset < entry.Size; {
		count := int64(len(buffer))
		if count > entry.Size-offset {
			count = entry.Size - offset
		}
		n, err := h.ReadAt(ctx, buffer[:count], offset)
		if err != nil && err != io.EOF {
			return err
		}
		if int64(n) != count {
			return io.ErrUnexpectedEOF
		}
		if _, err = f.Write(buffer[:n]); err != nil {
			return err
		}
		offset += int64(n)
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(target, entry.Mode.Perm()&0700); err != nil {
		return err
	}
	complete = true
	return nil
}
func (v *View) InitialFileNames() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := []string{}
	for name, e := range v.state.Initial {
		if e.Mode.IsRegular() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
