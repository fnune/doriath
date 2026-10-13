package profile

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

const graphQLProfile = `
[[http]]
host = "api.github.com"
default = "approve"

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

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "mutation", fields = ["mergePullRequest"] }
body_contains = ["pullRequestId"]
action = "approve"
summary = "merge"
`

func gqlBody(t *testing.T, query string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGraphQLRules(t *testing.T) {
	p, err := loader(fstest.MapFS{"p.toml": file(graphQLProfile)}, fstest.MapFS{}).Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Intercepted("api.github.com")
	if !h.NeedsBody("POST", "/graphql") || h.NeedsBody("GET", "/graphql") {
		t.Error("graphql rules must ask for the body of POST /graphql only")
	}
	cases := map[string]struct {
		body string
		want string
	}{
		"query":                {gqlBody(t, "query { viewer { login } }"), "read"},
		"shorthand query":      {gqlBody(t, "{ viewer { login } }"), "read"},
		"named with variables": {`{"query":"query Q($n: String!) { repository(name: $n) { id } }","operationName":"Q","variables":{"n":"x"}}`, "read"},
		"routine mutation":     {gqlBody(t, "mutation { createPullRequest(input: {}) { pullRequest { url } } }"), "routine"},
		"two routine fields":   {gqlBody(t, "mutation { a: addComment(input: {}) { clientMutationId } createPullRequest(input: {}) { clientMutationId } }"), "routine"},
		"other mutation":       {gqlBody(t, "mutation { createCommitOnBranch(input: {}) { commit { oid } } }"), ""},
		"routine plus other":   {gqlBody(t, "mutation { createPullRequest(input: {}) { clientMutationId } createRef(input: {}) { clientMutationId } }"), ""},
		"alias of a routine name": {
			gqlBody(t, "mutation { createPullRequest: createCommitOnBranch(input: {}) { commit { oid } } }"), "",
		},
		"merge with id": {gqlBody(t, `mutation { mergePullRequest(input: {pullRequestId: "x"}) { clientMutationId } }`), "merge"},
		"merge without the body string": {
			gqlBody(t, "mutation { mergePullRequest(input: {}) { clientMutationId } }"), "",
		},
		"inline fragment": {gqlBody(t, "mutation { ... on Mutation { addComment(input: {}) { clientMutationId } } }"), "routine"},
		"fragment spread": {gqlBody(t, "mutation { ...M } fragment M on Mutation { addComment(input: {}) { clientMutationId } }"), "routine"},
		"mutation behind a fragment spread": {
			gqlBody(t, "mutation { addComment(input: {}) { clientMutationId } ...M } fragment M on Mutation { ...N } fragment N on Mutation { createRef(input: {}) { clientMutationId } }"), "",
		},
		"query with a mutation fragment": {gqlBody(t, "query { viewer { login } } mutation { ...M } fragment M on Mutation { addComment(input: {}) { clientMutationId } }"), ""},
		"missing fragment":               {gqlBody(t, "mutation { ...M }"), ""},
		"fragment cycle":                 {gqlBody(t, "mutation { ...A } fragment A on Mutation { ...B } fragment B on Mutation { ...A }"), ""},
		"duplicate fragment":             {gqlBody(t, "mutation { ...A } fragment A on Mutation { addComment { x } } fragment A on Mutation { createRef { x } }"), ""},
		"mutation in comments and strings": {
			gqlBody(t, "# mutation { createRef }\nquery { search(query: \"mutation { createRef }\", type: ISSUE) { issueCount } }"), "read",
		},
		"query and mutation in one document": {gqlBody(t, "query A { viewer { login } } mutation B { createRef(input: {}) { clientMutationId } }"), ""},
		"operation name does not narrow":     {`{"query":"query A { viewer { login } } mutation B { createRef(input: {}) { clientMutationId } }","operationName":"A"}`, ""},
		"batched reads":                      {`[{"query":"{ viewer { login } }"},{"query":"query { rateLimit { remaining } }"}]`, "read"},
		"batched with a mutation":            {`[{"query":"{ viewer { login } }"},{"query":"mutation { createRef(input: {}) { clientMutationId } }"}]`, ""},
		"batched with a persisted query":     {`[{"query":"{ viewer { login } }"},{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}]`, ""},
		"empty batch":                        {`[]`, ""},
		"persisted query":                    {`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`, ""},
		"null query":                         {`{"query":null}`, ""},
		"query not a string":                 {`{"query":["mutation { createRef }"]}`, ""},
		"second query key":                   {`{"query":"{ viewer { login } }","query":"mutation { createRef { x } }"}`, ""},
		"differently cased query key":        {`{"query":"{ viewer { login } }","Query":"mutation { createRef { x } }"}`, ""},
		"escaped mutation":                   {`{"query":"mutation { createRef { x } }"}`, ""},
		"invalid json":                       {`{"query":`, ""},
		"trailing data":                      {gqlBody(t, "{ viewer { login } }") + `{"query":"mutation { createRef { x } }"}`, ""},
		"not graphql":                        {gqlBody(t, "mutation {"), ""},
		"empty":                              {"", ""},
		"deep nesting":                       {gqlBody(t, strings.Repeat("{a", 100000)+strings.Repeat("}", 100000)), ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, ok := h.Decide("POST", "/graphql", []byte(tc.body))
			if tc.want == "" {
				if ok || r.Action != ActionApprove {
					t.Fatalf("matched %q, want the host default", r.Summary)
				}
				return
			}
			if !ok || r.Summary != tc.want {
				t.Fatalf("got %q (matched %v), want %q", r.Summary, ok, tc.want)
			}
		})
	}
}

func TestDescribeGraphQL(t *testing.T) {
	got := DescribeGraphQL([]byte(`[{"query":"{ viewer { login } }"},{"query":"mutation { b: createRef { x } addComment { x } }"}]`))
	if got != "query viewer; mutation addComment,createRef" {
		t.Fatalf("got %q", got)
	}
	if got := DescribeGraphQL([]byte("nope")); got != "" {
		t.Fatalf("got %q for a body that is not GraphQL", got)
	}
}

func TestGraphQLRuleValidation(t *testing.T) {
	cases := map[string]string{
		`graphql = { operation = "write" }`:                      `graphql operation "write"`,
		`graphql = { fields = ["a"] }`:                           `graphql operation ""`,
		`graphql = { operation = "mutation", fields = [] }`:      "graphql fields",
		`graphql = { operation = "mutation", fields = ["a b"] }`: `graphql field "a b"`,
		`graphql = { operation = "query", type = "x" }`:          "unknown keys",
	}
	for rule, want := range cases {
		profile := "[[http]]\nhost = \"a.com\"\n[[http.rules]]\npath = \"/graphql\"\naction = \"allow\"\n" + rule
		_, err := loader(fstest.MapFS{"p.toml": file(profile)}, fstest.MapFS{}).Load("p")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to contain %q", rule, err, want)
		}
	}
}
