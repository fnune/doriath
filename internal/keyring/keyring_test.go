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

func TestASecretNameWithSeparatorsRoundTrips(t *testing.T) {
	gokeyring.MockInit()
	for _, name := range []string{"forgejo:fnune:repos:write", "api.v2", "my_token"} {
		if err := (Desktop{}).Write("work", name, secret.NewValue([]byte("v-"+name))); err != nil {
			t.Fatal(err)
		}
		if v, err := (Desktop{}).Read("work", name); err != nil || string(v.Reveal()) != "v-"+name {
			t.Errorf("%s = %q, %v", name, v.Reveal(), err)
		}
		if _, err := (Logins{}).Read("work", name); !errors.Is(err, secret.ErrNotInKeyring) {
			t.Errorf("%s: a login reads the secret: %v", name, err)
		}
	}
	if _, err := (Desktop{}).Read("work", "forgejo"); !errors.Is(err, secret.ErrNotInKeyring) {
		t.Errorf("a prefix of a name reads the entry: %v", err)
	}
}
