package keyring

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"

	"github.com/fnune/doriath/internal/secret"
)

const (
	secretService = "doriath"
	loginService  = "doriath-oauth"
)

// Desktop keeps the keyring secrets of profiles in the keyring of your
// desktop.
type Desktop struct{}

// Logins keeps the OAuth logins of profiles in the keyring. It uses another
// service than Desktop, so a login and a keyring secret with one name never
// share an entry.
type Logins struct{}

func (Desktop) Read(profile, name string) (secret.Value, error) {
	return read(secretService, profile, name)
}

func (Desktop) Write(profile, name string, v secret.Value) error {
	return write(secretService, profile, name, v)
}

func (Logins) Read(profile, name string) (secret.Value, error) {
	return read(loginService, profile, name)
}

func (Logins) Write(profile, name string, v secret.Value) error {
	return write(loginService, profile, name, v)
}

func read(service, profile, name string) (secret.Value, error) {
	v, err := keyring.Get(service, entry(profile, name))
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return secret.Value{}, secret.ErrNotInKeyring
	case err != nil:
		return secret.Value{}, fmt.Errorf("read the keyring: %w", err)
	}
	return secret.NewValue([]byte(v)), nil
}

func write(service, profile, name string, v secret.Value) error {
	if err := keyring.Set(service, entry(profile, name), string(v.Reveal())); err != nil {
		return fmt.Errorf("write to the keyring: %w", err)
	}
	return nil
}

func entry(profile, name string) string {
	return profile + "/" + name
}
