package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyCannotBeExpandedFromRemoteInvocation(t *testing.T) {
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	root := t.TempDir()
	b, _ := json.Marshal(Config{Root: root})
	if _, err := Handle(context.Background(), Request{Action: "configure", Input: b, Context: Invocation{Origin: "remote"}}, nil); err == nil {
		t.Fatal("remote policy expansion accepted")
	}
	if _, err := Handle(context.Background(), Request{Action: "configure", Input: b, Context: Invocation{Origin: "local"}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestInputPolicyRejectsBothDirectionsOfStorageOverlap(t *testing.T) {
	storage := t.TempDir()
	t.Setenv("FLEET_PLUGIN_DATA_DIR", storage)
	child := filepath.Join(storage, "nested")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{storage, child, filepath.Dir(storage)} {
		b, _ := json.Marshal(Config{Root: root})
		if _, err := Handle(context.Background(), Request{Action: "configure", Input: b, Context: Invocation{Origin: "local"}}, nil); err == nil {
			t.Fatal("overlapping source accepted: " + root)
		}
	}
}
func TestSnapshotHasNoWriteThroughAndDiffIncludesDeletes(t *testing.T) {
	root, work := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := snapshot(root, work)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(work, "a"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "a"))
	if string(b) != "original" {
		t.Fatal("write leaked to input")
	}
	if err = os.Remove(filepath.Join(work, "a")); err != nil {
		t.Fatal(err)
	}
	delta, err := changes(work, before)
	if err != nil || len(delta) != 1 || delta[0].Operation != "deleted" {
		t.Fatalf("diff: %#v %v", delta, err)
	}
}
func TestSnapshotRejectsSymlinkInput(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(outside, []byte("secret"), 0600)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip(err)
	}
	if _, err := snapshot(root, t.TempDir()); err == nil {
		t.Fatal("input symlink accepted")
	}
}
func TestCommandEnvironmentDropsFleetAndProviderCredentials(t *testing.T) {
	t.Setenv("FLEET_TOKEN", "not-in-child")
	t.Setenv("OPENAI_API_KEY", "not-in-child")
	t.Setenv("FLEET_PLUGIN_ACTIVITY_TOKEN", "not-in-child")
	for _, entry := range commandEnvironment(t.TempDir()) {
		if strings.Contains(entry, "not-in-child") {
			t.Fatal("credential leaked")
		}
	}
}
func TestWorkspaceIDCannotEscapeStorage(t *testing.T) {
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	for _, id := range []string{"../", strings.Repeat("x", 32), "/tmp"} {
		if _, err := workspaceDir(id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}

func TestActivityEmitterReportsUnacknowledgedRecords(t *testing.T) {
	t.Setenv("FLEET_PLUGIN_ACTIVITY_URL", "http://127.0.0.1:1")
	t.Setenv("FLEET_PLUGIN_ACTIVITY_TOKEN", "test-fixture-capability")
	emit, status := ActivityEmitter()
	emit("process", "started", "fixture", nil)
	if status() == nil {
		t.Fatal("activity delivery failure silently accepted")
	}
}
