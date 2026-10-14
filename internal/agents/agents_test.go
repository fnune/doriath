package agents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fnune/girdle/internal/profile"
)

func TestMCPConfig(t *testing.T) {
	data, err := MCPConfig([]profile.MCPServer{
		{Name: "bazel", Command: []string{"bazel-mcp", "--stdio"}, Env: map[string]string{"A": "1"}},
		{Name: "notion", URL: "https://mcp.notion.com/mcp", Secret: "notion"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	bazel, notion := got.MCPServers["bazel"], got.MCPServers["notion"]
	if bazel["command"] != "bazel-mcp" || bazel["args"].([]any)[0] != "--stdio" || notion["type"] != "http" || notion["url"] != "https://mcp.notion.com/mcp" {
		t.Fatalf("%s", data)
	}
	if _, ok := notion["headers"]; ok {
		t.Fatal("the token is the proxy's to add, never the agent's")
	}
}

func TestPlantCopiesOnlyTheListedKeysOnce(t *testing.T) {
	dir := t.TempDir()
	source, dest := filepath.Join(dir, "you.json"), filepath.Join(dir, "profile", "state.json")
	if err := os.WriteFile(source, []byte(`{"hasCompletedOnboarding":true,"oauthAccount":{"email":"you@example.com"},"mcpServers":{"x":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	seeds := []Seed{{Source: source, Dest: dest, Keys: []string{"hasCompletedOnboarding"}}}
	if err := Plant(seeds); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["hasCompletedOnboarding"] != true {
		t.Fatalf("seeded %s", data)
	}
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	if err := os.WriteFile(dest, []byte(`{"theme":"mine"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Plant(seeds); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dest); string(data) != `{"theme":"mine"}` {
		t.Fatalf("a profile's own state must never be overwritten: %s", data)
	}
	if err := Plant([]Seed{{Source: filepath.Join(dir, "missing.json"), Dest: filepath.Join(dir, "other.json")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.json")); err == nil {
		t.Error("a missing source must plant nothing")
	}
}

func TestPlantNeverWritesThroughALinkOrFromBadJSON(t *testing.T) {
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "you.json"), filepath.Join(dir, "broken.json")
	for path, body := range map[string]string{good: `{"theme":"dark"}`, bad: `{"theme":`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere, link := filepath.Join(dir, "elsewhere.json"), filepath.Join(dir, "link.json")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	fromBad := filepath.Join(dir, "from-bad.json")
	if err := Plant([]Seed{
		{Source: good, Dest: link, Keys: []string{"theme"}},
		{Source: bad, Dest: fromBad, Keys: []string{"theme"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{elsewhere, fromBad} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s was planted", path)
		}
	}
}
