// Package ui holds the look that doriath's pages share: the design tokens,
// the component styles, the ornaments and the fonts. The approvals page
// serves it, and the documentation site builds from the same files.
package ui

import "embed"

//go:embed tokens.css components.css ornaments.svg icon.svg icon-waiting.svg fonts
var Assets embed.FS

// Icon is the approvals page's icon, which the tray shows too. The waiting
// icon has a mark for requests that wait for an answer.
func Icon(waiting bool) []byte {
	name := "icon.svg"
	if waiting {
		name = "icon-waiting.svg"
	}
	data, err := Assets.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}
