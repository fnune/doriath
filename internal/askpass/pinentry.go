package askpass

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fnune/doriath/internal/secret"
)

// Pinentry is the dialog of GnuPG, which most desktops install. doriath
// speaks its Assuan protocol on standard input and output.
type Pinentry struct {
	Path string
}

func (p Pinentry) Ask(ctx context.Context, profile, name string) (secret.Value, error) {
	cmd := exec.CommandContext(ctx, p.Path)
	detach(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return secret.Value{}, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return secret.Value{}, err
	}
	if err := cmd.Start(); err != nil {
		return secret.Value{}, fmt.Errorf("ask with pinentry: %w", err)
	}
	value, err := converse(in, bufio.NewReader(out), prompt(profile, name))
	_ = in.Close()
	if waitErr := cmd.Wait(); err == nil && waitErr != nil {
		err = waitErr
	}
	if err != nil {
		return secret.Value{}, fmt.Errorf("ask with pinentry: %w", dialogError(ctx, err))
	}
	return secret.NewValue(value), nil
}

func converse(w io.Writer, r *bufio.Reader, description string) ([]byte, error) {
	if _, err := response(r); err != nil {
		return nil, err
	}
	for _, c := range []string{"SETTITLE " + escape(title), "SETDESC " + escape(description), "SETPROMPT Value:"} {
		if _, err := request(w, r, c); err != nil {
			return nil, err
		}
	}
	value, err := request(w, r, "GETPIN")
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintln(w, "BYE")
	return value, nil
}

func request(w io.Writer, r *bufio.Reader, command string) ([]byte, error) {
	if _, err := fmt.Fprintln(w, command); err != nil {
		return nil, err
	}
	return response(r)
}

func response(r *bufio.Reader) ([]byte, error) {
	var data []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read the answer of pinentry: %w", err)
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			return data, nil
		case strings.HasPrefix(line, "D "):
			data = append(data, unescape(line[2:])...)
		case strings.HasPrefix(line, "ERR ") && strings.Contains(strings.ToLower(line), "cancel"):
			return nil, ErrDismissed
		case strings.HasPrefix(line, "ERR "):
			return nil, fmt.Errorf("pinentry: %s", line[4:])
		}
	}
}

func escape(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func unescape(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(b))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}
