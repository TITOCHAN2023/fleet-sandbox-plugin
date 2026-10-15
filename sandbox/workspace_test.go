package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func workspaceFixture(t *testing.T) (string, string, string) {
	t.Helper()
	t.Setenv("FLEET_PLUGIN_DATA_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	dir, err := workspaceDir(id)
	if err != nil {
		t.Fatal(err)
	}
	view := filepath.Join(dir, "view")
	if err = os.MkdirAll(view, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := snapshot(root, view)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveWorkspace(dir, Workspace{ID: id, State: "running", Created: time.Now().UnixMilli(), InputRoot: root, Before: before}); err != nil {
		t.Fatal(err)
	}
	return id, root, view
}
func TestWorkspaceRecoveryDistinguishesLiveAndInterruptedTasks(t *testing.T) {
	id, _, _ := workspaceFixture(t)
	_, release, err := lockedWorkspace(id)
	if err != nil {
		t.Fatal(err)
	}
	live, err := listWorkspaces()
	if err != nil || len(live) != 1 || live[0].State != "running" {
		t.Fatalf("live: %#v %v", live, err)
	}
	if _, err = inspectWorkspace(id); err == nil {
		t.Fatal("inspection did not respect active lock")
	}
	b, _ := json.Marshal(map[string]string{"sandbox_id": id})
	if _, err = Handle(context.Background(), Request{Action: "discard", Input: b, Context: Invocation{Origin: "local"}}, nil); err == nil {
		t.Fatal("discard raced live task")
	}
	release()
	recovered, err := listWorkspaces()
	if err != nil || len(recovered) != 1 || recovered[0].State != "interrupted" {
		t.Fatalf("recovery: %#v %v", recovered, err)
	}
	result, err := inspectWorkspace(id)
	if err != nil || result.State != "interrupted" || result.OK {
		t.Fatalf("inspection: %#v %v", result, err)
	}
}
func TestExportPreservesOriginalAndReportsInputConflicts(t *testing.T) {
	id, root, view := workspaceFixture(t)
	if err := os.Remove(filepath.Join(view, "input.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(view, "new.txt"), []byte("result"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("new user edit"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "export")
	out, err := exportWorkspace(context.Background(), ExportInput{id, destination}, func(string, string, string, map[string]any) {})
	if err != nil || len(out.Conflicts) != 1 {
		t.Fatalf("export: %#v %v", out, err)
	}
	original, _ := os.ReadFile(filepath.Join(root, "input.txt"))
	output, _ := os.ReadFile(filepath.Join(destination, "files", "new.txt"))
	if string(original) != "new user edit" || string(output) != "result" {
		t.Fatal("export changed original or lost result")
	}
	var manifest struct {
		Changes []Change `json:"changes"`
	}
	b, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	deleted := false
	for _, change := range manifest.Changes {
		if change.Path == "input.txt" && change.Operation == "deleted" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("deletion missing from manifest")
	}
	if _, err = exportWorkspace(context.Background(), ExportInput{id, destination}, func(string, string, string, map[string]any) {}); err == nil {
		t.Fatal("existing export overwritten")
	}
}
func TestExportRejectsRemoteCallAndSymlinkOrHardLinkResults(t *testing.T) {
	id, _, view := workspaceFixture(t)
	input, _ := json.Marshal(ExportInput{id, filepath.Join(t.TempDir(), "out")})
	if _, err := Handle(context.Background(), Request{Action: "export", Input: input, Context: Invocation{Origin: "remote"}}, nil); err == nil {
		t.Fatal("remote export allowed")
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []func(string, string) error{os.Symlink, os.Link} {
		target := filepath.Join(view, "result-link")
		if err := link(outside, target); err != nil {
			continue
		}
		destination := filepath.Join(t.TempDir(), "out")
		if _, err := exportWorkspace(context.Background(), ExportInput{id, destination}, func(string, string, string, map[string]any) {}); err == nil {
			t.Fatal("linked result exported")
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatal("failed export was published")
		}
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPublishDirectoryCannotReplaceAnExistingEmptyDirectory(t *testing.T) {
	parent := t.TempDir()
	source, destination := filepath.Join(parent, "source"), filepath.Join(parent, "destination")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectory(source, destination); err == nil {
		t.Fatal("existing directory replaced")
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatal("failed publication removed source")
	}
}
