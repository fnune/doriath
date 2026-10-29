package main

import (
	"testing"

	"github.com/fnune/doriath/internal/config"
)

func TestOnlyPlasmaGetsTheSymbolicTrayIconsBecauseOnlyPlasmaRecolorsThem(t *testing.T) {
	p := config.Paths{Runtime: "/run/user/1000/doriath"}
	for desktop, want := range map[string]string{
		"KDE":         "/run/user/1000/doriath/tray",
		"ubuntu:KDE":  "/run/user/1000/doriath/tray",
		"GNOME":       "",
		"sway":        "",
		"":            "",
		"KDEish:XFCE": "",
	} {
		if got := symbolicTrayPath(p, desktop); got != want {
			t.Errorf("%q: path = %q, want %q", desktop, got, want)
		}
	}
}
