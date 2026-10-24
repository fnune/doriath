package main

import (
	"bytes"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/allowed"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/term"
)

type memoryGrants map[allowed.Key][]string

func (m memoryGrants) Grants(key allowed.Key) ([]string, bool, error) {
	g, ok := m[key]
	return g, ok, nil
}

func (m memoryGrants) Allow(key allowed.Key, grants []string) error {
	m[key] = slices.Clone(grants)
	return nil
}

var appKey = allowed.Key{Profile: "app", Repository: "/home/u/src/app"}

func appProfile(hosts ...string) *profile.Profile {
	p := &profile.Profile{Name: "app", Description: "the app", Sources: map[string][]string{}}
	for _, h := range hosts {
		p.Egress.Allow = append(p.Egress.Allow, profile.HostPattern(h))
		p.Sources["host "+h] = []string{"profile"}
	}
	return p
}

func confirm(t *testing.T, store memoryGrants, p *profile.Profile, answer string, terminal bool) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := confirmProfile(store, p, appKey, strings.NewReader(answer), &out, terminal)
	return out.String(), err
}

func TestANewProfileAsksAndKeepsYes(t *testing.T) {
	store := memoryGrants{}
	out, err := confirm(t, store, appProfile("a.example"), "y\n", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "You have not allowed profile app in /home/u/src/app yet") || !strings.Contains(out, "a.example") || !strings.Contains(out, "Allow? [y/N]") {
		t.Errorf("output:\n%s", out)
	}
	if _, seen, _ := store.Grants(appKey); !seen {
		t.Error("yes did not keep the profile")
	}
	if out, err := confirm(t, store, appProfile("a.example"), "", true); err != nil || out != "" {
		t.Errorf("an allowed profile asked again: %v\n%s", err, out)
	}
}

func TestAnyAnswerButYesRefuses(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "nope\n", ""} {
		store := memoryGrants{}
		if _, err := confirm(t, store, appProfile("a.example"), answer, true); err == nil {
			t.Errorf("answer %q started the session", answer)
		}
		if len(store) != 0 {
			t.Errorf("answer %q kept the profile", answer)
		}
	}
}

func TestAWiderProfileShowsOnlyWhatItAdds(t *testing.T) {
	store := memoryGrants{}
	if _, err := confirm(t, store, appProfile("a.example"), "y\n", true); err != nil {
		t.Fatal(err)
	}
	out, err := confirm(t, store, appProfile("a.example", "b.example"), "n\n", true)
	if err == nil {
		t.Fatal("no answered yes")
	}
	if !strings.Contains(out, "+ Egress.Allow: b.example") || strings.Contains(out, "+ Egress.Allow: a.example") {
		t.Errorf("output:\n%s", out)
	}
}

func TestANarrowerProfileStartsWithoutAskingAndAsksWhenItWidensAgain(t *testing.T) {
	store := memoryGrants{}
	if _, err := confirm(t, store, appProfile("a.example", "b.example"), "y\n", true); err != nil {
		t.Fatal(err)
	}
	if out, err := confirm(t, store, appProfile("a.example"), "", false); err != nil || out != "" {
		t.Fatalf("a narrower profile asked: %v\n%s", err, out)
	}
	if _, err := confirm(t, store, appProfile("a.example", "b.example"), "", false); err == nil {
		t.Fatal("b.example came back without an answer")
	}
}

func TestWithoutATerminalTheRefusalSaysHowToAllow(t *testing.T) {
	_, err := confirm(t, memoryGrants{}, appProfile("a.example"), "y\n", false)
	if err == nil || !strings.Contains(err.Error(), "doriath profiles allow app --current /home/u/src/app") {
		t.Fatalf("err = %v", err)
	}
}

func TestANewOrderShowsOnlyWhenNothingElseInTheListChanged(t *testing.T) {
	order := "HTTP[api.example].Rules" + profile.OrderSuffix + "abcd"
	rule := `HTTP[api.example].Rules: {"Action":"allow"}`
	if got := readableAdditions([]string{order}); !slices.Equal(got, []string{"HTTP[api.example].Rules: in a new order"}) {
		t.Errorf("order alone: %q", got)
	}
	if got := readableAdditions([]string{rule, order}); !slices.Equal(got, []string{rule}) {
		t.Errorf("with a new rule: %q", got)
	}
}

func TestProfilesAllowIsTheAnswerWithoutATerminal(t *testing.T) {
	l := &profile.Loader{Profiles: fstest.MapFS{"app.toml": {Data: []byte("[egress]\nallow = [\"a.example\"]\n")}}, Modules: []fs.FS{fstest.MapFS{}}, Home: "/home/u"}
	store, dir := memoryGrants{}, t.TempDir()
	var out bytes.Buffer
	if err := profilesAllow(l, store, "app", dir, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "a.example") || !strings.Contains(out.String(), "Allowed profile app.") {
		t.Errorf("output:\n%s", out.String())
	}
	prof, err := l.Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmProfile(store, prof, allowedKey(prof, dir), strings.NewReader(""), &out, false); err != nil {
		t.Fatalf("a session without a terminal still asks after profiles allow: %v", err)
	}
}

func TestTheFirstQuestionSummarizesEachKindOfEntryOnOneLine(t *testing.T) {
	p := appProfile("a.example", "b.example")
	p.Sources["env pass TERM"] = []string{"base"}
	p.Sources["env pass LANG"] = []string{"base"}
	p.Sources["env set NO_TELEMETRY"] = []string{"base"}
	out, _ := confirm(t, memoryGrants{}, p, "n\n", true)
	for _, want := range []string{"\nHosts\n  a.example, b.example\n", "\nEnvironment\n  pass  LANG, TERM\n  set   NO_TELEMETRY\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

func TestALongListWrapsUnderItsLabel(t *testing.T) {
	p := appProfile()
	for _, name := range []string{"AAAA", "BBBB", "CCCC", "DDDD"} {
		p.Sources["env pass "+name] = []string{"base"}
	}
	var out bytes.Buffer
	summarizeProfile(term.New(&out), &out, p, 22)
	want := "\nEnvironment\n  pass  AAAA, BBBB,\n        CCCC, DDDD\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestADroppedRestrictionAsksAndShowsTheLine(t *testing.T) {
	withDeny := appProfile("a.example")
	withDeny.HTTP = []profile.HTTPHost{{Host: "api.example", Default: profile.ActionApprove, Rules: []profile.Rule{{Method: "*", Path: "/admin/**", Action: profile.ActionDeny}}}}
	store := memoryGrants{}
	if _, err := confirm(t, store, withDeny, "y\n", true); err != nil {
		t.Fatal(err)
	}
	withoutDeny := appProfile("a.example")
	withoutDeny.HTTP = []profile.HTTPHost{{Host: "api.example", Default: profile.ActionApprove}}
	out, err := confirm(t, store, withoutDeny, "n\n", true)
	if err == nil {
		t.Fatal("a profile without the deny rule started without a question")
	}
	if !strings.Contains(out, "gives the jail more than when you allowed it") || !strings.Contains(out, `- HTTP[api.example].Rules: {"Action":"deny","Method":"*","Path":"/admin/**"}`) {
		t.Errorf("output:\n%s", out)
	}
	if _, err := confirm(t, store, withoutDeny, "y\n", true); err != nil {
		t.Fatal(err)
	}
	if out, err := confirm(t, store, withoutDeny, "", true); err != nil || out != "" {
		t.Errorf("the allowed profile asked again: %v\n%s", err, out)
	}
}

func TestTheFirstQuestionShowsSecretSourcesCredentialsAndSettings(t *testing.T) {
	p := appProfile("a.example")
	p.Sources["secret gh"] = []string{"profile"}
	p.Sources["source gh: command ./scripts/token.sh"] = []string{"profile"}
	p.Sources["credential api.example: gh for gh, curl"] = []string{"profile"}
	p.Sources["default api.example: allow"] = []string{"profile"}
	p.Sources["setting nix.daemon = true"] = []string{"profile"}
	p.Sources["setting hardening.landlock = false"] = []string{"profile"}
	out, _ := confirm(t, memoryGrants{}, p, "n\n", true)
	for _, want := range []string{
		"\nSecret sources\n  gh: command ./scripts/token.sh\n",
		"\nCredentials\n  api.example: gh for gh, curl\n",
		"\nHost defaults\n  api.example: allow\n",
		"\nSettings\n  hardening.landlock = false\n  nix.daemon = true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}
