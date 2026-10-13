//go:build bundled

package bundle

import _ "embed"

//go:embed assets/bwrap
var bwrap []byte
