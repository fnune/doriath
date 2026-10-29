package tray

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteSymbolicWritesAnIconForEachState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tray")
	if err := WriteSymbolic(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{IdleName, WaitingName} {
		if _, err := os.Stat(filepath.Join(dir, name+".svg")); err != nil {
			t.Error(err)
		}
	}
}

func TestEveryShapeOfTheSymbolicIconsTakesAColorOfThePanel(t *testing.T) {
	for _, name := range []string{IdleName, WaitingName} {
		data, err := symbolic.ReadFile("symbolic/" + name + ".svg")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Style struct {
				ID string `xml:"id,attr"`
			} `xml:"style"`
			Shapes []struct {
				XMLName xml.Name
				Class   string `xml:"class,attr"`
				Fill    string `xml:"fill,attr"`
				Stroke  string `xml:"stroke,attr"`
			} `xml:",any"`
		}
		if err := xml.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Style.ID != "current-color-scheme" {
			t.Errorf("%s: Plasma recolors only the stylesheet with id current-color-scheme, got %q", name, doc.Style.ID)
		}
		for _, s := range doc.Shapes {
			if s.XMLName.Local == "style" {
				continue
			}
			if !strings.HasPrefix(s.Class, "ColorScheme-") || (s.Fill != "currentColor" && s.Stroke != "currentColor") {
				t.Errorf("%s: a %s keeps its own color: class %q, fill %q, stroke %q", name, s.XMLName.Local, s.Class, s.Fill, s.Stroke)
			}
		}
	}
}
