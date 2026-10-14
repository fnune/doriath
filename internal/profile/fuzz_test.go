package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/fnune/girdle/internal/modules"
)

func FuzzHostPattern(f *testing.F) {
	for _, s := range [][2]string{
		{"api.github.com", "api.github.com"},
		{"api.github.com", "API.GitHub.com."},
		{"*.github.com", "api.github.com"},
		{"*.github.com", "github.com"},
		{"*.github.com", ".github.com"},
		{"*.github.com", "a..github.com"},
		{"*.githubusercontent.com", "evilgithubusercontent.com"},
		{"proxy.golang.org", "proxy.golang.org.evil.com"},
		{"10.0.0.1", "10.0.0.1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		p, err := ParseHostPattern(pattern)
		if err != nil {
			return
		}
		if strings.Trim(string(p), "abcdefghijklmnopqrstuvwxyz0123456789-.*") != "" {
			t.Fatalf("pattern %q parsed to %q, which holds more than host name characters", pattern, p)
		}
		if !p.Match(host) {
			return
		}
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		suffix, wildcard := strings.CutPrefix(string(p), "*.")
		if !wildcard {
			if h != string(p) {
				t.Fatalf("%q matched %q", p, host)
			}
			return
		}
		sub, ok := strings.CutSuffix(h, "."+suffix)
		if !ok || slices.Contains(strings.Split(sub, "."), "") {
			t.Fatalf("%q matched %q, which is not a subdomain of %s", p, host, suffix)
		}
	})
}

func FuzzPathPattern(f *testing.F) {
	for _, s := range [][2]string{
		{"/repos/*/*/pulls/*/merge", "/repos/a/b/pulls/1/merge"},
		{"/repos/*/*/pulls/*/merge", "/REPOS/a/b/PULLS/1/MERGE/"},
		{"/repos/*/*/pulls/*/merge", "/repos/a/b/pulls/1/merge?x=1"},
		{"/repos/*/*/releases", "/repos/a/b/releases/1"},
		{"/graphql", "/graphql#x"},
		{"/**", ""},
		{"/*", "0"},
		{"/a/**", "/a"},
		{"/a/**", "/a/b/c"},
		{"/", "/"},
		{"/a/", "/a//"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, path string) {
		if !utf8.ValidString(pattern) || !utf8.ValidString(path) {
			return
		}
		p, err := ParsePathPattern(pattern)
		if err != nil {
			return
		}
		if got, want := p.Match(path), pathOracle(pattern, path); got != want {
			t.Fatalf("%q.Match(%q) = %v, want %v", pattern, path, got, want)
		}
	})
}

// pathOracle states PathPattern's documented semantics as a regular
// expression, as a second implementation to compare against.
func pathOracle(pattern, path string) bool {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	segs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	rest := ""
	if segs[len(segs)-1] == "**" {
		segs, rest = segs[:len(segs)-1], "(/.*)?"
	}
	expr := make([]string, len(segs))
	for i, s := range segs {
		if s == "*" {
			expr[i] = "[^/]*"
		} else {
			expr[i] = regexp.QuoteMeta(s)
		}
	}
	prefix := "/" + strings.Join(expr, "/")
	if len(segs) == 0 {
		prefix = ""
		if path == "/" {
			path = ""
		}
	}
	return regexp.MustCompile(`(?is)\A` + prefix + rest + `\z`).MatchString(path)
}

const fuzzGraphQLHost = `
[[http]]
host = "api.github.com"
default = "approve"

[[http.rules]]
method = "POST"
path = "/graphql"
body_contains = ["mergePullRequest"]
action = "deny"
summary = "merge"

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "query" }
action = "allow"
summary = "read"

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "mutation", fields = ["createPullRequest", "addComment"] }
action = "allow"
summary = "routine"
`

var routineFields = []string{"createPullRequest", "addComment"}

func FuzzGraphQLDecide(f *testing.F) {
	for _, q := range []string{
		"query { viewer { login } }",
		"{ viewer { login } }",
		"mutation { createPullRequest(input: {}) { pullRequest { url } } }",
		"mutation { createPullRequest: createCommitOnBranch(input: {}) { commit { oid } } }",
		"mutation { ... on Mutation { addComment(input: {}) { clientMutationId } } }",
		"mutation { addComment(input: {}) { clientMutationId } ...M } fragment M on Mutation { ...N } fragment N on Mutation { createRef(input: {}) { clientMutationId } }",
		"query { viewer { login } } mutation { ...M } fragment M on Mutation { addComment(input: {}) { clientMutationId } }",
		"mutation { ...A } fragment A on Mutation { ...B } fragment B on Mutation { ...A }",
		"# mutation { createRef }\nquery { search(query: \"mutation { createRef }\", type: ISSUE) { issueCount } }",
		"subscription { x }",
	} {
		b, err := json.Marshal(map[string]string{"query": q})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, b := range []string{
		`{"query":"mutation{mergePullRequest(input:{}){clientMutationId}}"}`,
		`{"query":"{ viewer { login } }","query":"mutation { createRef { x } }"}`,
		`{"query":"{ viewer { login } }","Query":"mutation { createRef { x } }"}`,
		`[{"query":"{ viewer { login } }"},{"query":"mutation { createRef(input: {}) { clientMutationId } }"}]`,
		`[{"query":"{ viewer { login } }"},{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}]`,
		`{"query":"{ viewer { login } }"}{"query":"mutation { createRef { x } }"}`,
		`{"query":null}`,
		`[]`,
	} {
		f.Add([]byte(b))
	}
	p, err := loader(fstest.MapFS{"p.toml": file(fuzzGraphQLHost)}, fstest.MapFS{}).Load("p")
	if err != nil {
		f.Fatal(err)
	}
	h, _ := p.Intercepted("api.github.com")
	f.Fuzz(func(t *testing.T, body []byte) {
		rule, matched := h.Decide("POST", "/graphql", body)
		described := DescribeGraphQL(body)
		queries := oracleQueries(body)
		for _, q := range queries {
			if strings.Contains(q, "mergePullRequest") && rule.Summary != "merge" {
				t.Fatalf("a query naming mergePullRequest got %q (matched %v)", rule.Summary, matched)
			}
		}
		if !matched || rule.Summary == "merge" {
			return
		}
		if described == "" {
			t.Fatalf("rule %q matched a body that DescribeGraphQL does not see as GraphQL", rule.Summary)
		}
		for _, q := range queries {
			ops, ok := oracleOperations(q)
			if !ok {
				continue
			}
			for _, op := range ops {
				switch rule.Summary {
				case "read":
					if op.typ != GraphQLQuery {
						t.Fatalf("query-only rule matched a %s in %q", op.typ, q)
					}
				case "routine":
					if op.typ != GraphQLMutation {
						t.Fatalf("mutation rule matched a %s in %q", op.typ, q)
					}
					for _, name := range op.fields {
						if !slices.Contains(routineFields, name) {
							t.Fatalf("mutation rule for %v matched field %s in %q", routineFields, name, q)
						}
					}
				}
			}
		}
	})
}

// oracleQueries returns every value of a "query" key, in any case, at the
// top level of a GraphQL request or a batch of them, duplicates included.
func oracleQueries(body []byte) []string {
	var raw json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	objects := []json.RawMessage{raw}
	var batch []json.RawMessage
	if json.Unmarshal(raw, &batch) == nil {
		objects = batch
	}
	var out []string
	for _, obj := range objects {
		dec := json.NewDecoder(bytes.NewReader(obj))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			continue
		}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			var value json.RawMessage
			if dec.Decode(&value) != nil {
				break
			}
			var s string
			if key, _ := tok.(string); strings.EqualFold(key, "query") && json.Unmarshal(value, &s) == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

type oracleOperation struct {
	typ    GraphQLOperation
	fields []string
}

func oracleOperations(query string) ([]oracleOperation, bool) {
	doc, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: query}, maxGraphQLTokens)
	if err != nil {
		return nil, false
	}
	var out []oracleOperation
	for _, op := range doc.Operations {
		var fields []string
		if !topLevelFields(doc, op.SelectionSet, 0, &fields) {
			return nil, false
		}
		out = append(out, oracleOperation{typ: GraphQLOperation(op.Operation), fields: fields})
	}
	return out, true
}

func topLevelFields(doc *ast.QueryDocument, set ast.SelectionSet, depth int, out *[]string) bool {
	if depth > 64 {
		return false
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			*out = append(*out, s.Name)
		case *ast.InlineFragment:
			if !topLevelFields(doc, s.SelectionSet, depth+1, out) {
				return false
			}
		case *ast.FragmentSpread:
			for _, def := range doc.Fragments {
				if def.Name == s.Name && !topLevelFields(doc, def.SelectionSet, depth+1, out) {
					return false
				}
			}
		}
	}
	return true
}

func FuzzBodyContainsSeesThroughEscapes(f *testing.F) {
	f.Add("mutation{", "mergePullRequest", "(input:{}){x}}", uint64(0), false)
	f.Add("", "mergePullRequest", "", uint64(0xffff), false)
	f.Add("x", "mergePullRequest", "y", uint64(0b1010), true)
	f.Add("😀", "créer", "\n\"\\", uint64(0xaaaa), false)
	f.Fuzz(func(t *testing.T, prefix, needle, suffix string, escapes uint64, asKey bool) {
		if needle == "" || !utf8.ValidString(prefix+needle+suffix) {
			return
		}
		text := jsonEscaped(prefix+needle+suffix, escapes)
		body := `{"query":` + text + `}`
		if asKey {
			body = `{` + text + `:1}`
		}
		r := Rule{BodyContains: []string{needle}}
		if !r.matchBody([]byte(body)) {
			t.Fatalf("body_contains %q missed %s", needle, body)
		}
	})
}

// jsonEscaped writes s as a JSON string, spelling the runes whose bit is set
// in escapes as \u escapes, as a client hiding a word from a byte search
// would.
func jsonEscaped(s string, escapes uint64) string {
	var b strings.Builder
	b.WriteByte('"')
	for i, r := range []rune(s) {
		if escapes&(1<<(uint(i)%64)) == 0 && r >= 0x20 && r != '"' && r != '\\' {
			b.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, `\u%04x`, u)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func FuzzLoad(f *testing.F) {
	builtin, err := fs.Glob(modules.FS, "*.toml")
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range builtin {
		data, err := fs.ReadFile(modules.FS, name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add([]byte(`modules = ["m"]`), data)
		f.Add(data, []byte(""))
	}
	f.Add([]byte(fuzzGraphQLHost), []byte(""))
	f.Add([]byte(graphQLProfile), []byte(`[egress]`+"\n"+`allow = ["*.example.com"]`))
	f.Add([]byte("modules = [\"m\"]\n[[mounts]]\npath = \"~/x\"\nmode = \"rw\"\n[[caches]]\npath = \"~/.cache/go\"\n[secrets.k]\nfile = \"~/k\"\n[signing]\nkey = \"k\"\n"),
		[]byte("[[mounts]]\npath = \"/nix/store\"\nmode = \"clone\"\n[limits]\nmemory = \"50%\"\ncpu = \"200%\"\n"))
	f.Fuzz(func(t *testing.T, profileText, moduleText []byte) {
		l := &Loader{
			Profiles: fstest.MapFS{"p.toml": &fstest.MapFile{Data: profileText}},
			Modules:  []fs.FS{fstest.MapFS{"m.toml": &fstest.MapFile{Data: moduleText}}, modules.FS},
			Home:     "/home/u",
		}
		p, err := l.Load("p")
		again, errAgain := l.Load("p")
		if (err == nil) != (errAgain == nil) || !reflect.DeepEqual(p, again) {
			t.Fatalf("two loads disagree: %v, %v", err, errAgain)
		}
		if err != nil {
			return
		}
		checkLoaded(t, p)
	})
}

func checkLoaded(t *testing.T, p *Profile) {
	t.Helper()
	for _, m := range p.Mounts {
		if !filepath.IsAbs(m.Path) || filepath.Clean(m.Path) != m.Path {
			t.Fatalf("mount %q is not an absolute clean path", m.Path)
		}
		if m.Mode != ModeReadOnly && UnderTrustedRoot(m.Path+"/") {
			t.Fatalf("mount %q is %s under a trusted root", m.Path, m.Mode)
		}
	}
	for _, c := range p.Caches {
		if !strings.HasPrefix(c.Path, "/home/u/") || filepath.Clean(c.Path) != c.Path {
			t.Fatalf("cache %q is outside the home", c.Path)
		}
	}
	for _, d := range p.Devices {
		if !strings.HasPrefix(d, "/dev/") || filepath.Clean(d) != d {
			t.Fatalf("device %q is outside /dev", d)
		}
	}
	hosts := slices.Clone(p.Egress.Allow)
	for _, prog := range p.Egress.Programs {
		hosts = append(hosts, prog.Allow...)
	}
	for _, h := range p.HTTP {
		hosts = append(hosts, h.Host)
	}
	for _, h := range hosts {
		if again, err := ParseHostPattern(string(h)); err != nil || again != h {
			t.Fatalf("host pattern %q does not parse back to itself: %v", h, err)
		}
	}
	for _, h := range p.HTTP {
		if c := h.Credential; c != nil {
			if _, ok := p.Secrets[c.Secret]; !ok {
				t.Fatalf("http %s uses secret %q that the profile does not define", h.Host, c.Secret)
			}
		}
		for _, r := range h.Rules {
			if !methodPattern.MatchString(r.Method) {
				t.Fatalf("rule method %q", r.Method)
			}
			if again, err := ParsePathPattern(string(r.Path)); err != nil || again != r.Path {
				t.Fatalf("rule path %q does not parse back to itself: %v", r.Path, err)
			}
			if slices.Contains(r.BodyContains, "") {
				t.Fatal("an empty body_contains entry matches every body")
			}
			if g := r.GraphQL; g != nil && g.Fields != nil && len(g.Fields) == 0 {
				t.Fatal("an empty graphql fields list")
			}
		}
	}
	if p.SigningKey != "" {
		if _, ok := p.Secrets[p.SigningKey]; !ok {
			t.Fatalf("signing key %q is not a defined secret", p.SigningKey)
		}
	}
	for k := range p.Env.Set {
		if !envName.MatchString(k) {
			t.Fatalf("env name %q", k)
		}
	}
}
