package keyring

import (
	"errors"
	"testing"

	gokeyring "github.com/zalando/go-keyring"

	"github.com/fnune/doriath/internal/secret"
)

func TestALoginAndASecretOfOneNameDoNotShareAnEntry(t *testing.T) {
	gokeyring.MockInit()
	if err := (Desktop{}).Write("work", "linear", secret.NewValue([]byte("plain"))); err != nil {
		t.Fatal(err)
	}
	if _, err := (Logins{}).Read("work", "linear"); !errors.Is(err, secret.ErrNotInKeyring) {
		t.Fatalf("a login reads the secret of its name: %v", err)
	}
	if err := (Logins{}).Write("work", "linear", secret.NewValue([]byte("login"))); err != nil {
		t.Fatal(err)
	}
	if v, err := (Desktop{}).Read("work", "linear"); err != nil || string(v.Reveal()) != "plain" {
		t.Fatalf("the secret after a login = %q, %v", v.Reveal(), err)
	}
	if v, err := (Logins{}).Read("work", "linear"); err != nil || string(v.Reveal()) != "login" {
		t.Fatalf("the login = %q, %v", v.Reveal(), err)
	}
}
