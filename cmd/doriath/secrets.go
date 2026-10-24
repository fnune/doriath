package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

const secretsUsage = "secrets: usage: doriath secrets provide [--session ID] NAME"

func cmdSecrets(args []string, in *os.File, w io.Writer) error {
	if len(args) == 0 || args[0] != "provide" {
		return errors.New(secretsUsage)
	}
	flags := flag.NewFlagSet("secrets provide", flag.ContinueOnError)
	id := flags.String("session", "", "the session, when several run")
	operands, err := parseInterspersed(flags, args[1:])
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New(secretsUsage)
	}
	name := operands[0]
	p, err := paths()
	if err != nil {
		return err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return err
	}
	dir, err := pickSession(sessions, *id, p.Sessions(), func(id string) string {
		return cli.Line("secrets", "provide", "--session", id, name)
	})
	if err != nil {
		return err
	}
	value, err := readSecretValue(in, os.Stderr, name)
	if err != nil {
		return fmt.Errorf("secrets provide: %w", err)
	}
	if err := control.Call(context.Background(), filepath.Join(dir, session.ControlSocket), session.MethodProvide, session.ProvideParams{Name: name, Value: string(value)}, nil); err != nil {
		return fmt.Errorf("secrets provide: %w", err)
	}
	fmt.Fprintf(w, "Session %s uses this value for secret %s until it ends.\n", filepath.Base(dir), name)
	return nil
}

func readSecretValue(in *os.File, prompt io.Writer, name string) ([]byte, error) {
	termios, err := unix.IoctlGetTermios(int(in.Fd()), unix.TCGETS)
	if err != nil {
		data, err := io.ReadAll(in)
		return bytes.TrimRight(data, "\r\n"), err
	}
	quiet := *termios
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(in.Fd()), unix.TCSETS, &quiet); err != nil {
		return nil, err
	}
	defer func() {
		_ = unix.IoctlSetTermios(int(in.Fd()), unix.TCSETS, termios)
		fmt.Fprintln(prompt)
	}()
	fmt.Fprintf(prompt, "Value for secret %s: ", name)
	line, err := bufio.NewReader(in).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}
