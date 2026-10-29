package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

func cmdDescribe(args []string) error {
	broker := os.Getenv("DORIATH_BROKER")
	if broker == "" {
		return errors.New("describe: DORIATH_BROKER is not set; `doriath describe` runs inside a doriath session")
	}
	if len(args) == 0 {
		return errors.New(`describe: usage: doriath describe TEXT, such as doriath describe "Fix the login redirect"`)
	}
	if err := control.Call(context.Background(), broker, session.MethodDescribe, session.DescribeParams{Text: strings.Join(args, " ")}, nil); err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	return nil
}
