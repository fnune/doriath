package profile

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseForward(t *testing.T) {
	for in, want := range map[string][2]int{"3000": {3000, 3000}, "8080:3000": {8080, 3000}} {
		host, jail, err := ParseForward(in)
		if err != nil || host != want[0] || jail != want[1] {
			t.Errorf("%s = %d:%d, %v", in, host, jail, err)
		}
	}
	for _, bad := range []string{"", "x", "0", "70000", "80:", "80:x", "127.0.0.1:80:80", "80/udp", "8000-8010"} {
		if _, _, err := ParseForward(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestForwardsTakeANumberOrHostColonJail(t *testing.T) {
	p := mustLoad(t, "modules = [\"inbox\"]\n\n[[forward]]\nport = \"8080:3000\"\n", fstest.MapFS{
		"inbox.toml": file("[[forward]]\nname = \"Inbox\"\nport = 47123\n"),
	})
	want := []PortForward{{Name: "Inbox", Host: 47123, Jail: 47123}, {Host: 8080, Jail: 3000}}
	if !slices.Equal(p.Forwards, want) {
		t.Errorf("forwards %+v, want %+v", p.Forwards, want)
	}
}

func TestForwardsAreRefusedWhenTheyClash(t *testing.T) {
	for name, tc := range map[string]struct{ profile, want string }{
		"two jail ports": {"[[forward]]\nport = \"8080:3000\"\n\n[[forward]]\nport = 8080\n", "already forwards to port 3000"},
		"an address":     {"[[forward]]\nport = \"0.0.0.0:8080:80\"\n", "want a number"},
		"a list":         {"[[forward]]\nport = [8080]\n", "want a number such as 8080"},
	} {
		_, err := load(t, tc.profile, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestTheSameForwardTwiceIsOne(t *testing.T) {
	p := mustLoad(t, "modules = [\"inbox\"]\n\n[[forward]]\nport = 47123\n", fstest.MapFS{
		"inbox.toml": file("[[forward]]\nname = \"Inbox\"\nport = 47123\n"),
	})
	if len(p.Forwards) != 1 || p.Forwards[0].Name != "Inbox" {
		t.Errorf("forwards %+v", p.Forwards)
	}
}

func TestARepositoryProfileCannotForwardAPort(t *testing.T) {
	l := withRepository(loader(fstest.MapFS{"work.toml": file("")}, fstest.MapFS{}), fstest.MapFS{
		"dev.toml": file("[[forward]]\nport = 5432\n"),
	})
	_, err := l.Load("work+repo:dev")
	if err == nil || !strings.Contains(err.Error(), "cannot forward a port") {
		t.Errorf("err = %v", err)
	}
}
