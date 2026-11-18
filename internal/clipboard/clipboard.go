package clipboard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

const MaxSize = 64 << 20

type Source interface {
	Types(ctx context.Context) ([]string, error)
	Copy(ctx context.Context, mimeType string, w io.Writer) error
}

// Ask decides whether the jail may read the clipboard as mimeType. It
// returns an error when you refuse or do not answer.
type Ask func(ctx context.Context, mimeType string) error

var imageType = regexp.MustCompile(`^image/[A-Za-z0-9][A-Za-z0-9.+-]*$`)

// Images offers only the image types of src, and asks before each read.
// Text is what people copy passwords and tokens as, so it never passes.
func Images(src Source, ask Ask) Source {
	return images{src: src, ask: ask}
}

type images struct {
	src Source
	ask Ask
}

func (i images) Types(ctx context.Context) ([]string, error) {
	types, err := i.src.Types(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(types, func(t string) bool { return !imageType.MatchString(t) }), nil
}

func (i images) Copy(ctx context.Context, mimeType string, w io.Writer) error {
	if !imageType.MatchString(mimeType) {
		return fmt.Errorf("doriath passes only images from your clipboard, not %q", mimeType)
	}
	types, err := i.Types(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(types, mimeType) {
		return fmt.Errorf("your clipboard holds no %s", mimeType)
	}
	if err := i.ask(ctx, mimeType); err != nil {
		return err
	}
	lw := &limited{w: w, left: MaxSize}
	err = i.src.Copy(ctx, mimeType, lw)
	if lw.over {
		return fmt.Errorf("the clipboard holds more than %d bytes", MaxSize)
	}
	return err
}

type limited struct {
	w    io.Writer
	left int
	over bool
}

func (l *limited) Write(p []byte) (int, error) {
	if len(p) > l.left {
		l.over = true
		return 0, io.ErrShortWrite
	}
	l.left -= len(p)
	return l.w.Write(p)
}

type WlPaste struct {
	Bin string
	Env []string
}

var emptyClipboard = regexp.MustCompile(`(?i)nothing is copied|no selection`)

func (c WlPaste) Types(ctx context.Context) ([]string, error) {
	var out bytes.Buffer
	if err := c.run(ctx, &out, "--list-types"); err != nil {
		if emptyClipboard.MatchString(err.Error()) {
			return nil, nil
		}
		return nil, err
	}
	return strings.Fields(out.String()), nil
}

func (c WlPaste) Copy(ctx context.Context, mimeType string, w io.Writer) error {
	return c.run(ctx, w, "--no-newline", "--type", mimeType)
}

func (c WlPaste) run(ctx context.Context, w io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	cmd.Env = c.Env
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wl-paste %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
