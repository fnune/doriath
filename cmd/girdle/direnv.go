package main

import (
	_ "embed"
	"io"
)

//go:embed direnv.sh
var direnvLibrary string

// cmdDirenv prints girdle's direnv library, for ~/.config/direnv/lib.
func cmdDirenv(w io.Writer) error {
	_, err := io.WriteString(w, direnvLibrary)
	return err
}
