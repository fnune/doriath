package ui

import "embed"

//go:embed tokens.css components.css ornaments.svg icon.svg icon-waiting.svg fonts
var Assets embed.FS

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
