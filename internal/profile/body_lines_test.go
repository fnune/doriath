package profile

import (
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

func TestARuleMatchesALineThatStartsWithAPrefix(t *testing.T) {
	l := loader(fstest.MapFS{"p.toml": file("[[http]]\nhost = \"api.example\"\ndefault = \"allow\"\n\n[[http.rules]]\nmethod = \"POST\"\npath = \"/**\"\nbody_line_prefix = [\"/\", \"!\"]\naction = \"approve\"\n")}, nil)
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Intercepted("api.example")
	for body, want := range map[string]Action{
		`{"body":"/merge"}`:               ActionApprove,
		`{"body":"a\n\t!x"}`:              ActionApprove,
		`{"outer":{"list":["a","\r/b"]}}`: ActionApprove,
		`{"body":"a\n\u000b/b"}`:          ActionApprove,
		`{"body":"a\n\f/b"}`:              ActionApprove,
		`{"body":"a\n\u00a0/b"}`:          ActionApprove,
		`{"body":"a\n\u3000/b"}`:          ActionApprove,
		`{"body":"a/b"}`:                  ActionAllow,
		`{"body":" text /merge"}`:         ActionAllow,
		`not json`:                        ActionAllow,
	} {
		if got, _ := h.Decide("POST", "/x", []byte(body)); got.Action != want {
			t.Errorf("%s: %s, want %s", body, got.Action, want)
		}
	}
}

func TestAnEmptyLinePrefixIsRefused(t *testing.T) {
	l := loader(fstest.MapFS{"p.toml": file("[[http]]\nhost = \"api.example\"\n\n[[http.rules]]\nmethod = \"POST\"\npath = \"/**\"\nbody_line_prefix = [\"\"]\naction = \"approve\"\n")}, nil)
	if _, err := l.Load("p"); err == nil || !strings.Contains(err.Error(), "body_line_prefix") {
		t.Errorf("err = %v", err)
	}
}

func TestARuleMatchesAJSONFieldOnlyWhenItIsExactlyOneOfTheValues(t *testing.T) {
	l := loader(fstest.MapFS{"p.toml": file("[[http]]\nhost = \"api.example\"\ndefault = \"approve\"\n\n[[http.rules]]\nmethod = \"POST\"\npath = \"/**\"\nbody_json = { event = [\"COMMENT\", \"REQUEST_CHANGES\"] }\naction = \"allow\"\n")}, nil)
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Intercepted("api.example")
	for _, c := range []struct {
		query, body string
		want        Action
	}{
		{"", `{"event":"COMMENT"}`, ActionAllow},
		{"", `{"body":"x", "event": "REQUEST_CHANGES"}`, ActionAllow},
		{"", `{"event":"comment"}`, ActionApprove},
		{"", `{"event":"APPROVE"}`, ActionApprove},
		{"", `{}`, ActionApprove},
		{"", `{"event":["COMMENT"]}`, ActionApprove},
		{"", `{"event":"COMMENT","event":"APPROVE"}`, ActionApprove},
		{"", `{"event":"COMMENT","EVENT":"APPROVE"}`, ActionApprove},
		{"", `{"EVENT":"COMMENT"}`, ActionApprove},
		{"", `{"event":"COMMENT"} {"event":"APPROVE"}`, ActionApprove},
		{"", `{"event":"COMMENT"`, ActionApprove},
		{"", `["COMMENT"]`, ActionApprove},
		{"event=APPROVE", `{"event":"COMMENT"}`, ActionApprove},
		{"x=1", `{"body":"\"event\":\"COMMENT\"","event":"APPROVE"}`, ActionApprove},
	} {
		query, _ := url.ParseQuery(c.query)
		if got, _ := h.DecideWithQuery("POST", "/x", query, nil, []byte(c.body)); got.Action != c.want {
			t.Errorf("%q %s: %s, want %s", c.query, c.body, got.Action, c.want)
		}
	}
}
