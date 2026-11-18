package keyring

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"

	"github.com/fnune/doriath/internal/secret"
)

const service = "doriath"

type Desktop struct{}

func (Desktop) Read(profile, name string) (secret.Value, error) {
	v, err := keyring.Get(service, entry(profile, name))
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return secret.Value{}, secret.ErrNotInKeyring
	case err != nil:
		return secret.Value{}, fmt.Errorf("read the keyring: %w", err)
	}
	return secret.NewValue([]byte(v)), nil
}

func (Desktop) Write(profile, name string, v secret.Value) error {
	if err := keyring.Set(service, entry(profile, name), string(v.Reveal())); err != nil {
		return fmt.Errorf("write to the keyring: %w", err)
	}
	return nil
}

func entry(profile, name string) string {
	return profile + "/" + name
}
