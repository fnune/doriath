package wayland

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/clipboard"
)

type fakeClipboard struct {
	content map[string][]byte
}

func (f fakeClipboard) Types(context.Context) ([]string, error) {
	var out []string
	for t := range f.content {
		out = append(out, t)
	}
	return out, nil
}

func (f fakeClipboard) Copy(_ context.Context, mimeType string, w io.Writer) error {
	_, err := w.Write(f.content[mimeType])
	return err
}

type asks struct {
	mu     sync.Mutex
	types  []string
	refuse bool
}

func (a *asks) ask(_ context.Context, mimeType string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.types = append(a.types, mimeType)
	if a.refuse {
		return errors.New("refused")
	}
	return nil
}

func (a *asks) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.types...)
}

// serve starts a display for src and returns the environment that points
// wl-paste and wl-copy at it.
func serve(t *testing.T, src clipboard.Source) []string {
	t.Helper()
	for _, tool := range []string{"wl-paste", "wl-copy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	socket := filepath.Join(t.TempDir(), "wayland.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, l, src, func(err error) { t.Log(err) })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return []string{"WAYLAND_DISPLAY=" + socket, "XDG_RUNTIME_DIR=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
}

func run(t *testing.T, env []string, stdin string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatalf("%s %v did not finish: %s", name, args, stderr.String())
	}
	if err != nil {
		return string(out), errors.New(strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

var png = []byte("\x89PNG\r\n\x1a\nnot really")

func copied() fakeClipboard {
	return fakeClipboard{content: map[string][]byte{
		"image/png":  png,
		"text/plain": []byte("hunter2"),
	}}
}

func TestWlPasteListsOnlyTheImageTypes(t *testing.T) {
	a := &asks{}
	env := serve(t, clipboard.Images(copied(), a.ask))
	out, err := run(t, env, "", "wl-paste", "--list-types")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "image/png" {
		t.Errorf("types = %q", out)
	}
	if len(a.seen()) != 0 {
		t.Errorf("listing the types asked you: %v", a.seen())
	}
}

func TestWlPasteReadsTheImageOnceYouAllowIt(t *testing.T) {
	a := &asks{}
	env := serve(t, clipboard.Images(copied(), a.ask))
	out, err := run(t, env, "", "wl-paste", "--type", "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(png) {
		t.Errorf("read %q", out)
	}
	if seen := a.seen(); len(seen) != 1 || seen[0] != "image/png" {
		t.Errorf("asked for %v", seen)
	}
}

func TestWlPasteGetsNothingYouRefuse(t *testing.T) {
	a := &asks{refuse: true}
	env := serve(t, clipboard.Images(copied(), a.ask))
	if out, _ := run(t, env, "", "wl-paste", "--type", "image/png"); out != "" {
		t.Errorf("read %q after a refusal", out)
	}
}

func TestWlPasteNeverGetsText(t *testing.T) {
	a := &asks{}
	env := serve(t, clipboard.Images(copied(), a.ask))
	for _, args := range [][]string{nil, {"--type", "text/plain"}, {"--type", "text"}, {"--primary"}} {
		if out, _ := run(t, env, "", "wl-paste", args...); strings.Contains(out, "hunter2") {
			t.Errorf("wl-paste %v read the text", args)
		}
	}
	for _, asked := range a.seen() {
		if !strings.HasPrefix(asked, "image/") {
			t.Errorf("a text read asked you for %s", asked)
		}
	}
}

func TestWlPasteSeesAnEmptyClipboard(t *testing.T) {
	env := serve(t, clipboard.Images(fakeClipboard{content: map[string][]byte{"text/plain": []byte("x")}}, (&asks{}).ask))
	if out, err := run(t, env, "", "wl-paste", "--list-types"); err == nil || out != "" {
		t.Errorf("a clipboard without images listed %q, %v", out, err)
	}
}

func TestWlCopyCannotSetYourClipboard(t *testing.T) {
	src := copied()
	env := serve(t, clipboard.Images(src, (&asks{}).ask))
	_, _ = run(t, env, "rm -rf ~", "wl-copy", "--foreground", "--type", "image/png")
	out, err := run(t, env, "", "wl-paste", "--type", "image/png")
	if err != nil || out != string(png) {
		t.Errorf("after wl-copy the clipboard reads %q, %v", out, err)
	}
}
