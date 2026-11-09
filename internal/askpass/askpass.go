// Package askpass asks you for the value of a secret in a dialog of your
// desktop.
package askpass

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/secret"
)

const title = "doriath"

var ErrDismissed = errors.New("you closed the dialog without a value")

func prompt(profile, name string) string {
	return fmt.Sprintf("Enter the value of secret %s for profile %s. doriath keeps it in the keyring of your desktop.", name, profile)
}

// Program is a dialog that takes the prompt as its last argument and prints
// your answer, such as the program in SSH_ASKPASS.
type Program struct {
	Argv []string
}

func (p Program) Ask(ctx context.Context, profile, name string) (secret.Value, error) {
	cmd := exec.CommandContext(ctx, p.Argv[0], slices.Concat(p.Argv[1:], []string{prompt(profile, name)})...)
	detach(cmd)
	out, err := cmd.Output()
	if err != nil {
		return secret.Value{}, fmt.Errorf("ask with %s: %w", filepath.Base(p.Argv[0]), dialogError(ctx, err))
	}
	return secret.NewValue(out), nil
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = time.Second
}

func dialogError(ctx context.Context, err error) error {
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("no answer in time: %w", ctx.Err())
	case errors.As(err, &exit):
		return ErrDismissed
	}
	return err
}
