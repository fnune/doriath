// Package modules holds the built-in modules that profiles build on.
package modules

import "embed"

//go:embed *.toml
var FS embed.FS

// Builtins load into every profile before its own layers. Each one only
// refuses, warns on or holds paths, so that no profile can leave it out.
var Builtins = []string{"private-paths"}
