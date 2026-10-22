package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirenvLibraryWritesAShim(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	bin, project, cache := filepath.Join(root, "bin"), filepath.Join(root, "my project's"), filepath.Join(root, "cache")
	for _, d := range []string{bin, project} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake := "#!/bin/sh\nprintf '%s\\n' \"$@\"\nprintf 'PATH=%s\\n' \"$PATH\"\n"
	if err := os.WriteFile(filepath.Join(bin, "doriath"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(root, "doriath.sh")
	if err := os.WriteFile(lib, []byte(direnvLibrary), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
log_error() { echo "error: $*" >&2; }
PATH_add() { PATH="$1:$PATH"; }
. "$1"
cd "$2" && use_doriath work deploy --command agent && cd / && agent --flag "two words"
`
	cmd := exec.Command("bash", "-c", script, "bash", lib, project)
	cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "XDG_CACHE_HOME=" + cache, "HOME=" + root}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{"run", "--profile", "work+deploy", "--current", project, "--", "agent", "--flag", "two words"}
	if len(lines) != len(want)+1 || strings.Join(lines[:len(want)], "|") != strings.Join(want, "|") {
		t.Fatalf("doriath got:\n%s", out)
	}
	if strings.Contains(lines[len(want)], filepath.Join(cache, "doriath", "shims")) {
		t.Errorf("the shim must take itself off PATH, or the command could find it again: %s", lines[len(want)])
	}
}

func TestDirenvLibraryAsksTheProfileForTheAgentCommand(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	bin, project := filepath.Join(root, "bin"), filepath.Join(root, "project")
	for _, d := range []string{bin, project} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake := "#!/bin/sh\nif [ \"$1 $2\" = '__agent-command work' ]; then echo someagent; exit 0; fi\nif [ \"$1\" = __agent-command ]; then exit 1; fi\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "doriath"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(root, "doriath.sh")
	if err := os.WriteFile(lib, []byte(direnvLibrary), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
log_error() { echo "error: $*" >&2; }
PATH_add() { PATH="$1:$PATH"; }
. "$1"
cd "$2" && use_doriath work && cd / && someagent hello
use_doriath other || echo refused
`
	cmd := exec.Command("bash", "-c", script, "bash", lib, project)
	cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "XDG_CACHE_HOME=" + filepath.Join(root, "cache"), "HOME=" + root}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "--\nsomeagent\nhello\n") {
		t.Errorf("the shim does not run the profile's agent command:\n%s", got)
	}
	if !strings.Contains(got, "--command") || !strings.Contains(got, "refused") {
		t.Errorf("a profile without an agent command must fail and name --command:\n%s", got)
	}
}
