package claude

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var hook = filepath.Join("cache", "market", "lint", "1.0.0", "hooks", "run.sh")

func pluginsOfYourOwn(t *testing.T) (real, private string) {
	t.Helper()
	root := t.TempDir()
	real, private = filepath.Join(root, "real", "plugins"), filepath.Join(root, "private", "plugins")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(real, hook)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, hook), []byte("lint\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(private), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyPluginsIn(real, private); err != nil {
		t.Fatal(err)
	}
	return real, private
}

func TestPluginScriptsStayRunnable(t *testing.T) {
	_, private := pluginsOfYourOwn(t)
	info, err := os.Stat(filepath.Join(private, hook))
	if err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("%v, %v", info, err)
	}
}

func TestAPluginTheJailEditsIsReplacedEvenWithItsTimeReset(t *testing.T) {
	real, private := pluginsOfYourOwn(t)
	original, err := os.Stat(filepath.Join(real, hook))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, hook), []byte("exfiltrate\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(private, hook), time.Now(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := copyPluginsIn(real, private); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(private, hook)); string(got) != "lint\n" {
		t.Errorf("hook = %q", got)
	}
}

func TestAPluginTheJailPlantsIsGoneNextSession(t *testing.T) {
	real, private := pluginsOfYourOwn(t)
	planted := filepath.Join(private, "cache", "market", "evil", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyPluginsIn(real, private); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planted); err == nil {
		t.Error("planted plugin survived")
	}
	if entries, _ := os.ReadDir(filepath.Dir(private)); len(entries) != 1 {
		t.Errorf("staging folders left behind: %v", entries)
	}
}

func TestNoPluginsOfYourOwnClearsTheProfilesCopy(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "plugins")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "planted.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyPluginsIn(filepath.Join(root, "missing"), private); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(private); err != nil || len(entries) != 0 {
		t.Errorf("entries %v, %v", entries, err)
	}
}
