package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

func TestHomeManagerConfig(t *testing.T) {
	dir := os.Getenv("DORIATH_HOME_MANAGER_FIXTURES")
	if dir == "" {
		t.Skip("run through the home-manager-module flake check")
	}
	defaults := User{
		Approvals: Approvals{ToolWait: time.Minute},
		Desktop:   Desktop{Notifications: true, Tray: true},
		Terminal:  Terminal{Title: true, Bar: true},
	}
	headless := defaults
	headless.Desktop = Desktop{}
	hostWait := 30 * time.Second
	configured := User{
		Approvals: Approvals{HostWait: &hostWait, ToolWait: 90 * time.Second},
		Terminal:  Terminal{Env: map[string]string{"HERDR_AGENT": "{command}"}},
	}
	zeroWait := defaults
	zeroWait.Approvals.HostWait = new(time.Duration)

	for name, want := range map[string]User{
		"defaults":   defaults,
		"headless":   headless,
		"configured": configured,
		"zero-wait":  zeroWait,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".toml")
			got, err := LoadUser(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
			if got.DefaultHostWait() != want.DefaultHostWait() {
				t.Fatalf("host wait: got %s, want %s", got.DefaultHostWait(), want.DefaultHostWait())
			}
		})
	}

	var f userFile
	metadata, err := toml.DecodeFile(filepath.Join(dir, "configured.toml"), &f)
	if err != nil {
		t.Fatal(err)
	}
	var checkKeys func(reflect.Type, []string)
	checkKeys = func(typ reflect.Type, path []string) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			if !metadata.IsDefined(path...) {
				t.Errorf("home-manager fixture does not cover %s", strings.Join(path, "."))
			}
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
	checkKeys(reflect.TypeFor[userFile](), nil)
}
