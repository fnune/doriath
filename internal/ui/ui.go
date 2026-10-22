// Package ui holds the look that doriath's pages share: the design tokens,
// the component styles, the ornaments and the fonts. The approvals page
// serves it, and the documentation site builds from the same files.
package ui

import "embed"

//go:embed tokens.css components.css ornaments.svg fonts
var Assets embed.FS
