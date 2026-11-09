package askpass

import "github.com/fnune/doriath/internal/secret"

// New returns the dialog of macOS, which osascript opens.
func New(func(string) string, func(string) (string, error)) secret.Asker {
	return Program{Argv: []string{
		"/usr/bin/osascript",
		"-e", "on run argv",
		"-e", `display dialog (item 1 of argv) default answer "" with hidden answer with title "` + title + `"`,
		"-e", "return text returned of result",
		"-e", "end run",
	}}
}
