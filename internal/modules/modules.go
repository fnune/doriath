// Package modules holds the built-in modules that profiles build on.
package modules

import "embed"

//go:embed *.toml
var FS embed.FS
