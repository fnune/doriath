package askpass

import "github.com/fnune/doriath/internal/secret"

func New(getenv func(string) string, lookPath func(string) (string, error)) secret.Asker {
	if getenv("WAYLAND_DISPLAY") == "" && getenv("DISPLAY") == "" {
		return nil
	}
	if program := getenv("SSH_ASKPASS"); program != "" {
		return Program{Argv: []string{program}}
	}
	if path, err := lookPath("pinentry"); err == nil {
		return Pinentry{Path: path}
	}
	return nil
}
