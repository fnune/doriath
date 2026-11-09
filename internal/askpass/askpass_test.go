package askpass

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dialog")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAProgramGetsThePromptAndGivesTheAnswer(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "prompt")
	p := Program{Argv: []string{script(t, `printf '%s' "$1" > `+seen+`; printf 'tok\n'`)}}
	v, err := p.Ask(context.Background(), "work", "forge")
	if err != nil || string(v.Reveal()) != "tok\n" {
		t.Fatalf("Ask = %q, %v", v.Reveal(), err)
	}
	if got, _ := os.ReadFile(seen); !strings.Contains(string(got), "secret forge for profile work") {
		t.Errorf("prompt = %q", got)
	}
}

func TestAProgramThatExitsWithAnErrorWasDismissed(t *testing.T) {
	_, err := Program{Argv: []string{script(t, "exit 1")}}.Ask(context.Background(), "work", "forge")
	if !errors.Is(err, ErrDismissed) {
		t.Errorf("err = %v", err)
	}
}

func TestADialogHasNoTerminalToFallBackTo(t *testing.T) {
	p := Program{Argv: []string{script(t, `if (: < /dev/tty) 2>/dev/null; then printf tty; else printf none; fi`)}}
	v, err := p.Ask(context.Background(), "work", "forge")
	if err != nil || string(v.Reveal()) != "none" {
		t.Errorf("Ask = %q, %v", v.Reveal(), err)
	}
}

const fakePinentry = `echo "OK Pleased to meet you"
while read -r cmd rest; do
  case "$cmd" in
    SETDESC) printf '%s' "$rest" > "$(dirname "$0")/desc"; echo OK ;;
    GETPIN) GETPIN_REPLY ;;
    BYE) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
`

func pinentry(t *testing.T, getpin string) (Pinentry, string) {
	path := script(t, strings.Replace(fakePinentry, "GETPIN_REPLY", getpin, 1))
	return Pinentry{Path: path}, filepath.Join(filepath.Dir(path), "desc")
}

func TestPinentryGivesTheDecodedAnswer(t *testing.T) {
	p, desc := pinentry(t, `echo "D t%25k"; echo OK`)
	v, err := p.Ask(context.Background(), "work", "forge")
	if err != nil || string(v.Reveal()) != "t%k" {
		t.Fatalf("Ask = %q, %v", v.Reveal(), err)
	}
	if got, _ := os.ReadFile(desc); !strings.Contains(string(got), "secret forge for profile work") {
		t.Errorf("description = %q", got)
	}
}

func TestPinentryCancelledWasDismissed(t *testing.T) {
	p, _ := pinentry(t, `echo "ERR 83886179 Operation cancelled <Pinentry>"`)
	if _, err := p.Ask(context.Background(), "work", "forge"); !errors.Is(err, ErrDismissed) {
		t.Errorf("err = %v", err)
	}
}

func TestEscapeKeepsEachRequestOnOneLine(t *testing.T) {
	if got := escape("a%b\nc\r"); got != "a%25b%0Ac%0D" {
		t.Errorf("escape = %q", got)
	}
}
