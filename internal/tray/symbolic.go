package tray

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

const (
	IdleName    = "doriath-idle"
	WaitingName = "doriath-waiting"
)

//go:embed symbolic/*.svg
var symbolic embed.FS

// WriteSymbolic writes the symbolic icons to dir, for a status area that
// looks icons up by name there.
func WriteSymbolic(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("write the tray icons: %w", err)
	}
	for _, name := range []string{IdleName, WaitingName} {
		data, err := symbolic.ReadFile("symbolic/" + name + ".svg")
		if err != nil {
			return fmt.Errorf("write the tray icons: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".svg"), data, 0o600); err != nil {
			return fmt.Errorf("write the tray icons: %w", err)
		}
	}
	return nil
}
