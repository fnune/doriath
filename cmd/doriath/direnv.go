package main

import (
	_ "embed"
	"io"
)

//go:embed direnv.sh
var direnvLibrary string

func cmdDirenv(w io.Writer) error {
	_, err := io.WriteString(w, direnvLibrary)
	return err
}
