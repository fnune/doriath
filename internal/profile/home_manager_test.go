package profile

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestHomeManagerSecrets(t *testing.T) {
	path := os.Getenv("DORIATH_HOME_MANAGER_PROFILE")
	if path == "" {
		t.Skip("run through the home-manager-module flake check")
	}
	var l layer
	metadata, err := toml.DecodeFile(path, &l)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Secrets) == 0 {
		t.Fatal("home-manager fixture has no secrets")
	}
	var checkKeys func(reflect.Type, []string)
	checkKeys = func(typ reflect.Type, path []string) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			for name := range l.Secrets {
				if metadata.IsDefined(append([]string{"secrets", name}, path...)...) {
					return
				}
			}
			t.Errorf("home-manager fixture does not cover secrets.<name>.%s", strings.Join(path, "."))
			return
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			key, _, _ := strings.Cut(field.Tag.Get("toml"), ",")
			if key == "-" || !field.IsExported() {
				continue
			}
			if key == "" {
				key = field.Name
			}
			checkKeys(field.Type, append(append([]string(nil), path...), key))
		}
	}
	checkKeys(reflect.TypeFor[secretLayer](), nil)
}
