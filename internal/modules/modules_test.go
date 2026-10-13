package modules

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/girdle/internal/profile"
)

func TestEveryModuleLoads(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".toml"); ok {
			names = append(names, `"`+name+`"`)
		}
	}
	body := "modules = [" + strings.Join(names, ", ") + "]\n[secrets.github]\ncommand = [\"gh\", \"auth\", \"token\"]\n"
	l := &profile.Loader{
		Profiles: fstest.MapFS{"all.toml": {Data: []byte(body)}},
		Modules:  []fs.FS{FS},
		Home:     "/home/u",
	}
	p, err := l.Load("all")
	if err != nil {
		t.Fatal(err)
	}
	gh, ok := p.Intercepted("api.github.com")
	if !ok || gh.Credential == nil || gh.Credential.Secret != "github" {
		t.Fatalf("github module: %+v", gh)
	}
	merge, _ := gh.Decide("PUT", "/repos/a/b/pulls/1/merge", nil)
	if merge.Action != profile.ActionApprove {
		t.Errorf("merges must need approval, got %v", merge.Action)
	}
	if alias, _ := gh.Decide("PUT", "/repositories/123/pulls/1/merge", nil); alias.Action != profile.ActionApprove {
		t.Errorf("the /repositories alias must need approval too, got %v", alias.Action)
	}
	for _, req := range []struct{ method, path, body, want, summary string }{
		{"GET", "/repos/a/b/releases/1", "", "allow", ""},
		{"POST", "/repos/a/b/pulls", "", "allow", ""},
		{"POST", "/repos/a/b/actions/runs/1/rerun-failed-jobs", "", "allow", ""},
		{"PUT", "/repos/a/b/contents/README.md", "", "approve", ""},
		{"POST", "/repos/a/b/actions/workflows/ci.yml/dispatches", "", "approve", ""},
		{"POST", "/user/keys", "", "approve", ""},
		{"POST", "/gists", "", "approve", ""},
		{"PUT", "/repos/a/b/environments/prod/secrets/X", "", "deny", ""},
		{"POST", "/graphql", `{"query":"query { viewer { login } }"}`, "allow", ""},
		{"POST", "/graphql", `{"query":"mutation($i: CreatePullRequestInput!) { createPullRequest(input: $i) { pullRequest { url } } }"}`, "allow", ""},
		{"POST", "/graphql", `{"query":"mutation { addComment(input: {}) { clientMutationId } }"}`, "allow", ""},
		{"POST", "/graphql", `{"query":"mutation { createCommitOnBranch(input: {}) { commit { oid } } }"}`, "approve", ""},
		{"POST", "/graphql", `{"query":"mutation { addComment: createCommitOnBranch(input: {}) { commit { oid } } }"}`, "approve", ""},
		{"POST", "/graphql", `{"query":"mutation { mergePullRequest(input: {}) { clientMutationId } }"}`, "approve", "Merge a pull request"},
		{"POST", "/graphql", `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`, "approve", ""},
	} {
		got, _ := gh.Decide(req.method, req.path, []byte(req.body))
		if string(got.Action) != req.want || got.Summary != req.summary {
			t.Errorf("%s %s %s = %v %q, want %s %q", req.method, req.path, req.body, got.Action, got.Summary, req.want, req.summary)
		}
	}
	git, _ := p.Intercepted("github.com")
	if !git.Credential.AllowsBinary("/nix/store/x-git-2.54.0/libexec/git-core/git-remote-http") {
		t.Error("nix's git fetches over HTTPS as git-remote-http and needs the token")
	}
	if fetch, _ := git.Decide("POST", "/a/b/git-upload-pack", nil); fetch.Action != profile.ActionAllow {
		t.Errorf("fetch = %v, want allow", fetch.Action)
	}
	if push, _ := git.Decide("POST", "/a/b/git-receive-pack", nil); push.Action != profile.ActionApprove {
		t.Errorf("push = %v, want approve", push.Action)
	}
	if !p.Claude.DisableConnectors || !p.Podman {
		t.Error("claude and podman modules not applied")
	}
	if !slices.Contains(p.ContainerImages, "docker.io/library/*") || slices.Contains(p.ContainerImages, "*") {
		t.Errorf("podman images %v, want the official images and not any image", p.ContainerImages)
	}
}
