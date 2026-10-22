//go:build integration

package session_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Skipf("%s: %v", from, err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestACredentialReachesOnlyThePinnedFileAndSystemCode(t *testing.T) {
	curl, err := filepath.EvalSymlinks(lookPath("curl"))
	if err != nil {
		t.Skip("curl not installed")
	}
	libz, err := filepath.EvalSymlinks("/usr/lib/libz.so.1")
	if err != nil {
		t.Skip("no system libz to preload")
	}
	e := newEnv(t)
	tools := filepath.Join(e.work, "tools")
	copyFile(t, curl, filepath.Join(tools, "fetch"))
	copyFile(t, libz, filepath.Join(e.work, "lib", "libz.so.1"))
	e.binaries = `, binaries = ["curl", "` + tools + `/*"]`
	code, out := e.run(e.profile(""), `
T=`+tools+`
get() { "$@" -sS -o /dev/null https://api.github.com/$path; }
path=pinned get $T/fetch
cp $T/fetch $T/later && path=later get $T/later
path=preloaded LD_PRELOAD=`+filepath.Join(e.work, "lib", "libz.so.1")+` get curl
cp $T/fetch $T/rebuilt && mv $T/rebuilt $T/fetch && path=replaced get $T/fetch
echo done
`, nil)
	if code != 0 || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for path, wantToken := range map[string]bool{"/pinned": true, "/later": false, "/preloaded": false, "/replaced": false} {
		r := e.upstream.find(path)
		if r == nil {
			t.Errorf("%s never reached the host:\n%s", path, out)
			continue
		}
		if got := r.Header.Get("Authorization") == "Bearer real-token"; got != wantToken {
			t.Errorf("%s: credential %v, want %v", path, got, wantToken)
		}
	}
	audit, _ := os.ReadFile(e.paths.AuditLog())
	for _, want := range []string{"is not the file it was when the session started", "runs code from", "is not a file that the profile names"} {
		if !strings.Contains(string(audit), want) {
			t.Errorf("the audit log does not say %q", want)
		}
	}
}
