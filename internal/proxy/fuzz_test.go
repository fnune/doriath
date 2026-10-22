package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/url"
	"path"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/profile"
)

func FuzzInterceptedRequest(f *testing.F) {
	for _, s := range []struct{ method, target, body string }{
		{"PUT", "/repos/a/b/pulls/1/merge", ""},
		{"PUT", "/REPOS/a/b/PULLS/1/MERGE/", ""},
		{"PUT", "/repos/a/b//pulls/1/merge", ""},
		{"PUT", "/repos/a/b/./pulls/1/merge", ""},
		{"PUT", "/repos/a/x/../b/pulls/1/merge", ""},
		{"PUT", "/repos/a%2Fb/pulls/1/merge", ""},
		{"PUT", "/repos/a/b/pulls/1/m%65rge", ""},
		{"PUT", "/repos/a/b/pulls/1/merge;x=1", ""},
		{"PUT", "/repos/a/b/pulls/1/merge%3B", ""},
		{"PUT", "/repos/a/b/pulls/1/%2e%2e/1/merge", ""},
		{"PUT", "/repos/a\\b/pulls/1/merge", ""},
		{"put", "/repos/a/b/pulls/1/merge", ""},
		{"POST", "/repos/a/b/releases?x=1", `{"tag_name":"v1"}`},
		{"POST", "/graphql", `{"query":"{viewer{login}}"}`},
		{"POST", "/graphql", `{"query":"mutation{mergePullRequest(input:{}){clientMutationId}}"}`},
		{"GET", "/", ""},
		{"GET", "*", ""},
	} {
		f.Add(s.method, s.target, []byte(s.body))
	}
	l := &profile.Loader{Profiles: mapFS{"t.toml": testProfile}, Home: "/home/u"}
	p, err := l.Load("t")
	if err != nil {
		f.Fatal(err)
	}
	rules, _ := p.Intercepted("api.github.com")
	f.Fuzz(func(t *testing.T, method, target string, body []byte) {
		u, err := url.ParseRequestURI(target)
		if err != nil || method != strings.ToUpper(method) || !canonicalPath(u) {
			return
		}
		escaped := strings.ToLower(u.EscapedPath())
		if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || strings.ContainsAny(u.Path, `\;`) {
			t.Fatalf("canonical path %q hides a separator or a parameter", target)
		}
		segs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		for i, s := range segs {
			if s == "." || s == ".." || (s == "" && i != len(segs)-1) {
				t.Fatalf("canonical path %q has segment %q", target, s)
			}
		}
		if !rules.NeedsBody(method, u.Path) {
			body = nil
		}
		rule, matched := rules.Decide(method, u.Path, body)
		cleanRule, cleanMatched := rules.Decide(method, path.Clean("/"+u.Path), body)
		if matched != cleanMatched || !reflect.DeepEqual(rule, cleanRule) {
			t.Fatalf("%s %s decides %+v, its clean form %+v", method, target, rule, cleanRule)
		}
		if method == "PUT" && mergePath(u.Path) && rule.Action != profile.ActionDeny {
			t.Fatalf("PUT %s is a merge and got %s", target, rule.Action)
		}
	})
}

func mergePath(p string) bool {
	segs := strings.Split(strings.Trim(path.Clean("/"+p), "/"), "/")
	return len(segs) == 6 && strings.EqualFold(segs[0], "repos") && strings.EqualFold(segs[3], "pulls") && strings.EqualFold(segs[5], "merge")
}

func FuzzPeerHeader(f *testing.F) {
	f.Add(7, "/nix/store/x-gh/bin/gh", []byte("GET / HTTP/1.1\r\n"))
	f.Add(1, "/tmp/evil\n{\"pid\":1,\"exe\":\"/usr/bin/gh\"}", []byte("\n"))
	f.Add(-1, " \x00\"\\", []byte{})
	f.Add(0, "", []byte("DORIATH-PEER {\"pid\":2,\"exe\":\"/usr/bin/git\"}\n"))
	f.Fuzz(func(t *testing.T, pid int, exe string, payload []byte) {
		header := jailinit.PeerHeader(jailinit.Peer{PID: pid, Exe: exe})
		r := bufio.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(payload)))
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		id, ok := parsePeerHeader(line)
		if !ok || id.PID != pid {
			t.Fatalf("header %q parsed to %+v, %v", header, id, ok)
		}
		if utf8.ValidString(exe) && id.Exe != exe {
			t.Fatalf("exe %q came back as %q", exe, id.Exe)
		}
		rest, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(rest, payload) {
			t.Fatalf("the header took bytes of the payload: %q", rest)
		}
		if _, ok := parsePeerHeader(string(payload)); ok != strings.HasPrefix(string(payload), headerPrefix) {
			t.Fatalf("payload %q parsed as a header: %v", payload, ok)
		}
	})
}
