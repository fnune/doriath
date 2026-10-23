package main

import (
	"errors"
	"io"

	"github.com/fnune/doriath/internal/guide"
)

func cmdGuide(args []string, w io.Writer) error {
	if len(args) != 1 {
		return errors.New("guide: usage: doriath guide profile | skill")
	}
	switch args[0] {
	case "profile":
		_, err := io.WriteString(w, guide.Profile)
		return err
	case "skill":
		_, err := io.WriteString(w, guide.Skill)
		return err
	}
	return errors.New("guide: usage: doriath guide profile | skill")
}
