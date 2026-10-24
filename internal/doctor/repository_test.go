package doctor

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcstools"
)

type signs struct{}

func (signs) Name() string                       { return "jj" }
func (signs) HostSigns() string                  { return "signing.behavior = own" }
func (signs) Jail(vcstools.Jail) vcstools.Config { return vcstools.Config{} }

func repoOptions(t *testing.T, envrc string, profiles map[string]string) Options {
	t.Helper()
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	sub := filepath.Join(repo, "sub")
	for _, d := range []string{filepath.Join(repo, ".git"), sub} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if envrc != "" {
		if err := os.WriteFile(filepath.Join(repo, ".envrc"), []byte(envrc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fsys := fstest.MapFS{}
	for name, body := range profiles {
		fsys[name+".toml"] = &fstest.MapFile{Data: []byte(body)}
	}
	return Options{
		Paths:  config.Paths{Home: home},
		Loader: &profile.Loader{Profiles: fsys, Modules: []fs.FS{modules.FS}, Home: home},
		Dir:    sub,
		VCS:    []vcstools.Tool{signs{}},
	}
}

func details(results []Result) string {
	var b strings.Builder
	for _, r := range results {
		b.WriteString(string(r.Level) + " " + r.Name + ": " + r.Detail + "\n")
	}
	return b.String()
}

func TestARepositoryIsCheckedWithTheProfileItsEnvrcNames(t *testing.T) {
	opts := repoOptions(t, "use flake\nuse doriath app\n", map[string]string{
		"app":     "modules = [\"vcs-readonly\"]\n\n[secrets.key]\nfile = \"/k\"\n\n[signing]\nkey = \"key\"\n",
		"default": "modules = []\n",
	})
	got := details(repository(opts))
	for _, want := range []string{"ok repository " + filepath.Dir(opts.Dir) + " with profile app: the agent commits through the store", "ok signing: with the secret key"} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
}

func TestAnEnvrcThatComposesProfilesNamesThemAll(t *testing.T) {
	if got := useDoriath([]byte("use doriath work deploy --command agent\n")); got != "work+deploy" {
		t.Errorf("profile = %q", got)
	}
}

func TestARepositoryWithoutAProfileIsCheckedWithTheDefault(t *testing.T) {
	opts := repoOptions(t, "", map[string]string{"default": "modules = []\n"})
	got := details(repository(opts))
	if !strings.Contains(got, "problem repository") || !strings.Contains(got, "cannot find it") {
		t.Errorf("from a subdirectory, the jail shows only that:\n%s", got)
	}
	opts.Dir = filepath.Dir(opts.Dir)
	got = details(repository(opts))
	for _, want := range []string{"note repository", "with profile default: the agent reads it but cannot commit: add vcs-readwrite or vcs-readonly", "problem signing: profile default: your jj signs commits (signing.behavior = own)"} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
}

func TestOutsideARepositoryDoctorChecksNoRepository(t *testing.T) {
	opts := repoOptions(t, "", nil)
	opts.Dir = opts.Paths.Home
	if got := repository(opts); len(got) != 0 {
		t.Errorf("results:\n%s", details(got))
	}
	opts.Dir = filepath.Join(opts.Paths.Home, "repo")
	if got := details(repository(opts)); !strings.Contains(got, "note repository") || !strings.Contains(got, "use doriath PROFILE") {
		t.Errorf("without a default profile doctor says how to name one:\n%s", got)
	}
}
