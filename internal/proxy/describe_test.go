package proxy

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

const describedProfile = `
[[http]]
host = "api.github.com"
default = "approve"
repositories = ["/repos/*/*"]

[[http.rules]]
method = "PUT"
path = "/repos/*/*/pulls/*/merge"
action = "approve"
summary = "Merge pull request"
subject = "{3}#{5}"
link = { label = "Open PR", url = "https://github.com/{2}/{3}/pull/{5}" }
`

func heldRequest(t *testing.T, method, url, payload string) approval.Request {
	t.Helper()
	h := newHarnessWith(t, describedProfile)
	req, _ := http.NewRequest(method, url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	h.approver.mu.Lock()
	defer h.approver.mu.Unlock()
	if len(h.approver.requests) != 1 {
		t.Fatalf("approval requests = %+v", h.approver.requests)
	}
	return h.approver.requests[0]
}

func TestAHeldRequestNamesWhatItActsOnAndLinksToIt(t *testing.T) {
	got := heldRequest(t, http.MethodPut, "https://api.github.com/repos/acme/app/pulls/7/merge", `{"merge_method":"squash"}`)
	if got.Action != "Merge pull request" || got.Title() != "Merge pull request" {
		t.Errorf("action = %q", got.Action)
	}
	if want := (approval.Link{Label: "Open PR", URL: "https://github.com/acme/app/pull/7"}); got.Link != want {
		t.Errorf("link = %+v", got.Link)
	}
	if len(got.Facts) < 2 || got.Facts[0] != (approval.Fact{Label: "About", Value: "app#7", URL: got.Link.URL}) || got.Facts[1] != (approval.Fact{Label: "merge_method", Value: "squash"}) {
		t.Errorf("facts = %+v", got.Facts)
	}
}

func TestAnUnnamedMutationIsNamedByItsFieldAndShowsItsVariables(t *testing.T) {
	payload := `{"query":"mutation($input:RequestReviewsByLoginInput!){requestReviewsByLogin(input:$input){clientMutationId}}","variables":{"input":{"pullRequestId":"PR_1","userLogins":["alice","bob"]}}}`
	got := heldRequest(t, http.MethodPost, "https://api.github.com/graphql", payload)
	if got.Action != "Request reviews by login" {
		t.Errorf("action = %q", got.Action)
	}
	if !slices.Contains(got.Facts, approval.Fact{Label: "userLogins", Value: "alice, bob"}) || !slices.Contains(got.Facts, approval.Fact{Label: "pullRequestId", Value: "PR_1"}) {
		t.Errorf("facts = %+v", got.Facts)
	}
	if !strings.Contains(got.Details, `variables {"input":{"pullRequestId":"PR_1","userLogins":["alice","bob"]}}`) {
		t.Errorf("the raw request drops the variables: %q", got.Details)
	}
	if got.Link != (approval.Link{}) {
		t.Errorf("a request that no rule names gets no link: %+v", got.Link)
	}
}

func TestAnUnnamedRequestLeavesOutTheRepositoryItNamesAsAFact(t *testing.T) {
	got := heldRequest(t, http.MethodPost, "https://api.github.com/repos/acme/app/pulls/comments/9/reactions", `{"content":"+1"}`)
	if got.Action != "POST /pulls/comments/9/reactions" {
		t.Errorf("action = %q", got.Action)
	}
	if len(got.Facts) < 2 || got.Facts[0].Value != "app" || got.Facts[1] != (approval.Fact{Label: "content", Value: "+1"}) {
		t.Errorf("facts = %+v", got.Facts)
	}
}

func pushRule(t *testing.T) profile.Rule {
	t.Helper()
	u, err := profile.ParseLinkTemplate("https://github.com/{1}/{2}/tree/{ref}")
	if err != nil {
		t.Fatal(err)
	}
	return profile.Rule{Action: profile.ActionApprove, Summary: "Push", Link: &profile.RuleLink{Label: "Open branch", URL: u}}
}

func TestAPushNamesItsRepositoryAndBranchAndLinksToABranch(t *testing.T) {
	q := httpRequest{
		rule: pushRule(t), matched: true, method: "POST", path: "/o/r.git/git-receive-pack", repo: "/o/r",
		refs:   []refUpdate{{ref: "refs/heads/agent/fix", old: strings.Repeat("a", 40), new: strings.Repeat("b", 40)}},
		caller: Identity{Exe: "/nix/store/x-jj/bin/.jj-wrapped", Commands: []string{"jj git push", "zsh"}},
	}
	d := describe(q)
	if d.action != "Push" || d.link != (approval.Link{Label: "Open branch", URL: "https://github.com/o/r/tree/agent/fix"}) {
		t.Errorf("described = %+v", d)
	}
	want := []approval.Fact{
		{Label: "About", Value: "r agent/fix", URL: "https://github.com/o/r/tree/agent/fix"},
		{Label: "Change", Value: "update refs/heads/agent/fix aaaaaaaaaaaa..bbbbbbbbbbbb"},
		{Label: "Program", Value: "jj"},
	}
	if !slices.Equal(d.facts, want) || !slices.Equal(d.commands, []string{"jj git push", "zsh"}) {
		t.Errorf("facts = %+v, commands = %v", d.facts, d.commands)
	}

	q.refs = append(q.refs, refUpdate{ref: "refs/heads/main", old: strings.Repeat("a", 40), new: strings.Repeat("b", 40)})
	if d := describe(q); d.link != (approval.Link{}) || d.facts[0].Value != "r agent/fix, main" {
		t.Errorf("a push of two branches links to neither: %+v", d)
	}
}

func TestAnMCPCallIsNamedByItsTool(t *testing.T) {
	q := httpRequest{
		rule: profile.Rule{Action: profile.ActionApprove, Summary: "Call notion tool", MCPServer: "notion"}, matched: true, method: "POST", path: "/mcp",
		body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notion-update-page","arguments":{"page_id":"3e6f"}}}`),
	}
	d := describe(q)
	if d.action != "Update page" || len(d.facts) != 2 || d.facts[0].Value != "notion" || d.facts[1] != (approval.Fact{Label: "page_id", Value: "3e6f"}) {
		t.Errorf("described = %+v", d)
	}
}

func TestAHeldRequestBodyReachesTheUpstreamWhole(t *testing.T) {
	for _, payload := range []string{`{"content":"+1"}`, `{"body":"` + strings.Repeat("x", maxShownBody) + `"}`} {
		h := newHarnessWith(t, describedProfile)
		resp, err := h.client().Post("https://api.github.com/repos/acme/app/issues/1/reactions", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		if _, got := h.upstream.last(t); string(got) != payload {
			t.Errorf("the upstream got %d bytes of %d", len(got), len(payload))
		}
	}
}
