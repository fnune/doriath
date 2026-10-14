package profile_test

import (
	"io/fs"
	"net/http"
	"testing"
	"testing/fstest"

	"github.com/fnune/girdle/internal/modules"
	"github.com/fnune/girdle/internal/profile"
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
		"login":          {http.Header{"Authorization": {"Bearer sk-ant-oat01-abc"}}, profile.ActionAllow},
		"x-api-key":      {http.Header{"X-Api-Key": {"sk-ant-api03-abc"}}, profile.ActionDeny},
		"bearer api key": {http.Header{"Authorization": {"Bearer sk-ant-api03-abc"}}, profile.ActionDeny},
		"lowercase":      {http.Header{"Authorization": {"bearer SK-ANT-API03-abc"}}, profile.ActionDeny},
		"admin key":      {http.Header{"Authorization": {"Bearer sk-ant-admin01-abc"}}, profile.ActionDeny},
	} {
		if r, _ := h.DecideRequest("POST", "/v1/messages", tc.header, nil); r.Action != tc.want {
			t.Errorf("%s: %s, want %s", name, r.Action, tc.want)
		}
	}
}
