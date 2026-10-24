package profile_test

import (
	"io/fs"
	"net/http"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
)

func TestClaudeRefusesAPIKeysInEitherHeader(t *testing.T) {
	l := &profile.Loader{
		Profiles: fstest.MapFS{"p.toml": {Data: []byte(`modules = ["claude"]`)}},
		Modules:  []fs.FS{modules.FS},
		Home:     "/home/u",
	}
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, ok := p.Intercepted("api.anthropic.com")
	if !ok {
		t.Fatal("api.anthropic.com is not intercepted")
	}
	for name, tc := range map[string]struct {
		header http.Header
		want   profile.Action
	}{
		"login":           {http.Header{"Authorization": {"Bearer sk-ant-oat01-abc"}}, profile.ActionAllow},
		"x-api-key":       {http.Header{"X-Api-Key": {"sk-ant-api03-abc"}}, profile.ActionDeny},
		"bearer api key":  {http.Header{"Authorization": {"Bearer sk-ant-api03-abc"}}, profile.ActionDeny},
		"lowercase":       {http.Header{"Authorization": {"bearer SK-ANT-API03-abc"}}, profile.ActionDeny},
		"admin key":       {http.Header{"Authorization": {"Bearer sk-ant-admin01-abc"}}, profile.ActionDeny},
		"two spaces":      {http.Header{"Authorization": {"Bearer  sk-ant-api03-abc"}}, profile.ActionDeny},
		"a tab":           {http.Header{"Authorization": {" Bearer\tsk-ant-api03-abc"}}, profile.ActionDeny},
		"key after login": {http.Header{"Authorization": {"Bearer sk-ant-oat01-abc", "Bearer sk-ant-api03-abc"}}, profile.ActionDeny},
	} {
		if r, _ := h.DecideRequest("POST", "/v1/messages", tc.header, nil); r.Action != tc.want {
			t.Errorf("%s: %s, want %s", name, r.Action, tc.want)
		}
	}
}

func TestAnLFSUploadIsHeldHoweverItsJSONIsWritten(t *testing.T) {
	for _, forge := range []string{"github", "gitlab", "forgejo", "bitbucket"} {
		l := &profile.Loader{
			Profiles: fstest.MapFS{"p.toml": {Data: []byte("modules = [\"" + forge + "\"]\n[secrets." + forge + "]\ncommand = [\"true\"]\n")}},
			Modules:  []fs.FS{modules.FS},
			Home:     "/home/u",
		}
		p, err := l.Load("p")
		if err != nil {
			t.Fatal(err)
		}
		var h profile.HTTPHost
		for _, c := range p.HTTP {
			if slices.ContainsFunc(c.Rules, func(r profile.Rule) bool {
				return r.Path.Match("/o/r.git/info/lfs/objects/batch") && len(r.BodyContains) > 0
			}) {
				h = c
			}
		}
		for body, want := range map[string]profile.Action{
			`{"operation":"upload","objects":[]}`:                             profile.ActionApprove,
			`{"operation" : "upload"}`:                                        profile.ActionApprove,
			"{\"operation\":\n\t\"upload\"}":                                  profile.ActionApprove,
			`{"operation":"\u0075pload"}`:                                     profile.ActionApprove,
			`{"Operation":"upload"}`:                                          profile.ActionApprove,
			`{"operation":"download","operation":"upload"}`:                   profile.ActionApprove,
			`{"operation": "download", "objects": [{"oid": "a", "size": 1}]}`: profile.ActionAllow,
		} {
			if r, _ := h.Decide("POST", "/o/r.git/info/lfs/objects/batch", []byte(body)); r.Action != want {
				t.Errorf("%s %s: %s, want %s", forge, body, r.Action, want)
			}
		}
	}
}
