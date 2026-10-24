package clipboard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fake struct {
	types []string
	data  []byte
}

func (f fake) Types(context.Context) ([]string, error) { return f.types, nil }

func (f fake) Copy(_ context.Context, _ string, w io.Writer) error {
	_, err := w.Write(f.data)
	return err
}

func allow(context.Context, string) error { return nil }

func TestImagesOffersOnlyImageTypes(t *testing.T) {
	src := Images(fake{types: []string{"image/png", "text/plain", "image/../etc", "image/", "x-kde-passwordManagerHint", "image/svg+xml"}}, allow)
	got, err := src.Types(context.Background())
	if err != nil || !slices.Equal(got, []string{"image/png", "image/svg+xml"}) {
		t.Errorf("types = %v, %v", got, err)
	}
}

func TestImagesRefusesWhatIsNotAnOfferedImage(t *testing.T) {
	asked := false
	src := Images(fake{types: []string{"image/png", "text/plain"}, data: []byte("x")}, func(context.Context, string) error {
		asked = true
		return nil
	})
	for _, mimeType := range []string{"text/plain", "image/jpeg", "--list-types"} {
		var out bytes.Buffer
		if err := src.Copy(context.Background(), mimeType, &out); err == nil || out.Len() != 0 {
			t.Errorf("Copy(%s) = %v, %q", mimeType, err, out.String())
		}
	}
	if asked {
		t.Error("a read doriath refuses on its own asked you")
	}
}

func TestImagesReadsNothingYouRefuse(t *testing.T) {
	refused := errors.New("refused")
	src := Images(fake{types: []string{"image/png"}, data: []byte("png")}, func(context.Context, string) error { return refused })
	var out bytes.Buffer
	if err := src.Copy(context.Background(), "image/png", &out); !errors.Is(err, refused) || out.Len() != 0 {
		t.Errorf("Copy = %v, %q", err, out.String())
	}
}

func TestImagesStopsAtMaxSize(t *testing.T) {
	src := Images(fake{types: []string{"image/png"}, data: make([]byte, MaxSize+1)}, allow)
	var out bytes.Buffer
	if err := src.Copy(context.Background(), "image/png", &out); err == nil || !strings.Contains(err.Error(), "more than") || out.Len() != 0 {
		t.Errorf("Copy = %v, wrote %d bytes", err, out.Len())
	}
}

func fakeWlPaste(t *testing.T, script string) WlPaste {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "wl-paste")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return WlPaste{Bin: bin, Env: []string{"WAYLAND_DISPLAY=wayland-1"}}
}

func TestWlPasteReadsTypesAndContent(t *testing.T) {
	c := fakeWlPaste(t, `case "$*" in
"--list-types") printf 'image/png\ntext/plain\n' ;;
"--no-newline --type image/png") printf 'png from %s' "$WAYLAND_DISPLAY" ;;
*) echo "unexpected $*" >&2; exit 2 ;;
esac
`)
	types, err := c.Types(context.Background())
	if err != nil || !slices.Equal(types, []string{"image/png", "text/plain"}) {
		t.Fatalf("types = %v, %v", types, err)
	}
	var out bytes.Buffer
	if err := c.Copy(context.Background(), "image/png", &out); err != nil || out.String() != "png from wayland-1" {
		t.Errorf("Copy = %q, %v", out.String(), err)
	}
}

func TestWlPasteSeesAnEmptyClipboardAsNoTypes(t *testing.T) {
	c := fakeWlPaste(t, "echo 'Nothing is copied' >&2; exit 1\n")
	if types, err := c.Types(context.Background()); err != nil || len(types) != 0 {
		t.Errorf("types = %v, %v", types, err)
	}
	failing := fakeWlPaste(t, "echo 'Failed to connect to a Wayland server' >&2; exit 1\n")
	if _, err := failing.Types(context.Background()); err == nil || !strings.Contains(err.Error(), "Failed to connect") {
		t.Errorf("err = %v", err)
	}
}
