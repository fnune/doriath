package profile

import (
	"slices"
	"strings"
	"testing"
)

func TestHumanize(t *testing.T) {
	for in, want := range map[string]string{
		"requestReviewsByLogin": "Request reviews by login",
		"save_issue":            "Save issue",
		"update-page":           "Update page",
		"addPRReview":           "Add pr review",
		"x":                     "X",
		"":                      "",
	} {
		if got := Humanize(in); got != want {
			t.Errorf("Humanize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestALinkTemplateCannotLetTheRequestChooseTheSite(t *testing.T) {
	for _, bad := range []string{
		"https://{1}.example/x",
		"https://github.com{1}/x",
		"http://github.com/{1}",
		"javascript:{1}",
		"https://github.com",
		"https://github.com/{owner}",
	} {
		if _, err := ParseLinkTemplate(bad); err == nil {
			t.Errorf("%q loads", bad)
		}
	}
	if _, err := ParseLinkTemplate("https://github.com/{2}/{3}/pull/{5}"); err != nil {
		t.Error(err)
	}
}

func TestATemplateWithAMissingValueExpandsToNothing(t *testing.T) {
	tmpl := Template("{3}#{5} on {ref}")
	values := TemplateValues{Segments: PathSegments("/repos/o/r.git/pulls/7?x=1")}
	if got, ok := tmpl.Expand(values, func(s string) string { return s }); ok {
		t.Errorf("expanded without a ref: %q", got)
	}
	values.Ref = "main"
	if got, ok := tmpl.Expand(values, strings.ToUpper); !ok || got != "R#7 on MAIN" {
		t.Errorf("got %q, %v", got, ok)
	}
	if _, ok := Template("{9}").Expand(values, strings.ToUpper); ok {
		t.Error("a segment past the end of the path expanded")
	}
}

func TestArgumentsKeepTheClientsOrderAndLookInsideAnInputObject(t *testing.T) {
	got := GraphQLVariables([]byte(`{"query":"mutation{x}","variables":{"input":{"b":["alice","bob"],"a":true,"n":null,"deep":{"k":1}}}}`))
	want := []Argument{{"b", "alice, bob"}, {"a", "true"}, {"deep", `{"k":1}`}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	long := JSONArguments([]byte(`{"body":"` + strings.Repeat("word ", 40) + `"}`))
	if len(long) != 1 || !strings.HasSuffix(long[0].Value, "…") || len([]rune(long[0].Value)) != maxArgumentValue+1 {
		t.Errorf("a long value is not cut: %+v", long)
	}
	var many strings.Builder
	many.WriteString("{")
	for i := range 10 {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`"k` + string(rune('a'+i)) + `":"v"`)
	}
	many.WriteString("}")
	if got := JSONArguments([]byte(many.String())); len(got) != maxArguments {
		t.Errorf("got %d arguments", len(got))
	}
}

func TestARuleLoadsItsSubjectAndLink(t *testing.T) {
	p := mustLoad(t, `
[[http]]
host = "api.example.com"

[[http.rules]]
method = "PUT"
path = "/repos/*/*/pulls/*/merge"
action = "approve"
summary = "Merge pull request"
subject = "{3}#{5}"
link = { label = "Open PR", url = "https://example.com/{2}/{3}/pull/{5}" }
`, nil)
	r := p.HTTP[0].Rules[0]
	if r.Subject != "{3}#{5}" || r.Link == nil || r.Link.Label != "Open PR" || r.Link.URL != "https://example.com/{2}/{3}/pull/{5}" {
		t.Errorf("rule = %+v", r)
	}
	for _, bad := range []string{
		`subject = "{owner}"`,
		`link = { label = "Open PR", url = "https://{2}.example/x" }`,
		`link = { url = "https://example.com/{2}" }`,
	} {
		if _, err := load(t, `
[[http]]
host = "api.example.com"

[[http.rules]]
method = "PUT"
path = "/x"
action = "approve"
`+bad, nil); err == nil {
			t.Errorf("%s loads", bad)
		}
	}
}
