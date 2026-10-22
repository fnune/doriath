package modules

import (
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/profile"
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
	body := "modules = [" + strings.Join(names, ", ") + "]\n"
	for _, name := range []string{"github", "gitlab", "forgejo", "bitbucket"} {
		body += "[secrets." + name + "]\ncommand = [\"true\"]\n"
	}
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
	anthropic, ok := p.Intercepted("api.anthropic.com")
	if !ok {
		t.Fatal("the claude module must intercept api.anthropic.com")
	}
	withKey := http.Header{"X-Api-Key": {"sk-ant-agent"}}
	if r, _ := anthropic.DecideRequest("POST", "/v1/messages", withKey, nil); r.Action != profile.ActionDeny {
		t.Errorf("a request with an API key = %v, want deny", r.Action)
	}
	login := http.Header{"Authorization": {"Bearer from-the-login"}}
	if r, _ := anthropic.DecideRequest("POST", "/v1/messages", login, nil); r.Action != profile.ActionAllow {
		t.Errorf("a request with the login = %v, want allow", r.Action)
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

func TestForgeModulesHoldWritesAndRefuseSecrets(t *testing.T) {
	body := "modules = [\"gitlab\", \"forgejo\", \"bitbucket\"]\n"
	for _, name := range []string{"gitlab", "forgejo", "bitbucket"} {
		body += "[secrets." + name + "]\ncommand = [\"true\"]\n"
	}
	l := &profile.Loader{Profiles: fstest.MapFS{"f.toml": {Data: []byte(body)}}, Modules: []fs.FS{FS}, Home: "/home/u"}
	p, err := l.Load("f")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host, method, path, want, secretScheme, body string
	}{
		{"gitlab.com", "GET", "/api/v4/projects/group%2Fsub%2Fproj/merge_requests", "allow", "header", ""},
		{"gitlab.com", "PUT", "/api/v4/projects/42/merge_requests/7/merge", "approve", "header", ""},
		{"gitlab.com", "POST", "/api/v4/projects/42/hooks", "deny", "", ""},
		{"gitlab.com", "PUT", "/api/v4/groups/acme/sub/variables/TOKEN", "deny", "", ""},
		{"gitlab.com", "POST", "/api/graphql", "approve", "header", ""},
		{"gitlab.com", "POST", "/group/sub/proj.git/git-receive-pack", "approve", "basic", ""},
		{"gitlab.com", "POST", "/group/sub/proj.git/git-upload-pack", "allow", "basic", ""},
		{"codeberg.org", "POST", "/api/v1/repos/a/b/pulls/3/merge", "approve", "token", ""},
		{"codeberg.org", "PUT", "/api/v1/repos/a/b/actions/secrets/X", "deny", "", ""},
		{"codeberg.org", "POST", "/api/v1/repos/a/b/issues/1/comments", "allow", "token", ""},
		{"codeberg.org", "POST", "/a/b.git/git-receive-pack", "approve", "basic", ""},
		{"api.bitbucket.org", "POST", "/2.0/repositories/ws/repo/pullrequests/1/merge", "approve", "bearer", ""},
		{"api.bitbucket.org", "POST", "/2.0/repositories/ws/repo/hooks", "deny", "", ""},
		{"bitbucket.org", "POST", "/ws/repo.git/git-receive-pack", "approve", "basic", ""},
		{"gitlab.com", "POST", "/api/v4/projects/42/remote_mirrors", "deny", "", ""},
		{"gitlab.com", "PUT", "/api/v4/projects/42/transfer", "deny", "", ""},
		{"gitlab.com", "POST", "/api/v4/personal_access_tokens/self/rotate", "deny", "", ""},
		{"gitlab.com", "POST", "/api/v4/user/keys", "deny", "", ""},
		{"gitlab.com", "DELETE", "/api/v4/projects/42", "deny", "", ""},
		{"gitlab.com", "PUT", "/api/v4/projects/42", "approve", "header", ""},
		{"gitlab.com", "GET", "/api/v4/projects/42/repository/files/README.md", "allow", "header", ""},
		{"gitlab.com", "PUT", "/api/v4/projects/42/repository/files/README.md", "approve", "header", ""},
		{"gitlab.com", "POST", "/api/v4/projects/42/merge_requests/7/approve", "allow", "header", ""},
		{"gitlab.com", "POST", "/group/proj.git/info/lfs/objects/batch", "allow", "basic", ""},
		{"gitlab.com", "PUT", "/group/proj.git/gitlab-lfs/objects/abc/12", "allow", "basic", ""},
		{"codeberg.org", "GET", "/api/v1/repos/a/b/contents/README.md", "allow", "token", ""},
		{"codeberg.org", "PUT", "/api/v1/repos/a/b/contents/README.md", "approve", "token", ""},
		{"codeberg.org", "GET", "/api/v1/repos/a/b/actions/runners/registration-token", "deny", "", ""},
		{"codeberg.org", "POST", "/api/v1/repos/a/b/branch_protections", "deny", "", ""},
		{"codeberg.org", "POST", "/api/v1/repos/a/b/push_mirrors-sync", "deny", "", ""},
		{"codeberg.org", "PATCH", "/api/v1/repos/a/b/issues/comments/9", "allow", "token", ""},
		{"codeberg.org", "PUT", "/a/b.git/info/lfs/objects/abc", "allow", "basic", ""},
		{"api.bitbucket.org", "POST", "/2.0/repositories/ws/repo/branch-restrictions", "deny", "", ""},
		{"api.bitbucket.org", "PUT", "/2.0/repositories/ws/repo/permissions-config/users/x", "deny", "", ""},
		{"api.bitbucket.org", "DELETE", "/2.0/repositories/ws/repo", "deny", "", ""},
		{"api.bitbucket.org", "POST", "/2.0/repositories/ws/repo/pullrequests/1/decline", "allow", "bearer", ""},
		{"api.bitbucket.org", "DELETE", "/2.0/repositories/ws/repo/pullrequests/1/approve", "allow", "bearer", ""},
		{"bitbucket.org", "POST", "/ws/repo.git/info/lfs/objects/batch", "allow", "basic", `{"operation":"download","objects":[]}`},
		{"bitbucket.org", "POST", "/ws/repo.git/info/lfs/objects/batch", "approve", "basic", `{"operation":"upload","objects":[]}`},
		{"codeberg.org", "POST", "/a/b.git/info/lfs/objects/batch", "approve", "basic", `{"operation": "upload"}`},
	} {
		h, ok := p.Intercepted(c.host)
		if !ok {
			t.Fatalf("%s is not inspected", c.host)
		}
		rule, matched := h.Decide(c.method, c.path, []byte(c.body))
		if string(rule.Action) != c.want {
			t.Errorf("%s %s%s: %s, want %s", c.method, c.host, c.path, rule.Action, c.want)
			continue
		}
		if c.secretScheme == "" {
			continue
		}
		cred := h.Credential
		if matched && rule.Credential != nil {
			cred = rule.Credential
		}
		if cred == nil || string(cred.Scheme) != c.secretScheme {
			t.Errorf("%s %s%s: credential %+v, want the %s scheme", c.method, c.host, c.path, cred, c.secretScheme)
		}
	}
	for _, host := range []string{"gitlab.com", "codeberg.org", "bitbucket.org"} {
		if h, _ := p.Intercepted(host); !slices.Contains(h.Credential.Binaries, "git-lfs") {
			t.Errorf("%s: git-lfs gets no token: %v", host, h.Credential.Binaries)
		}
	}
	if bb, _ := p.Intercepted("bitbucket.org"); !slices.Contains(bb.SSH.Hosts, "ssh.bitbucket.org") {
		t.Errorf("bitbucket.org: the SSH remotes of ssh.bitbucket.org stay on SSH")
	}
	gitlab, _ := p.Intercepted("gitlab.com")
	if !gitlab.EncodedSlashes || gitlab.Repository("/api/v4/projects/42/merge_requests/7/merge") != "/api/v4/projects/42" {
		t.Errorf("gitlab.com: encoded slashes %v, repository %q", gitlab.EncodedSlashes, gitlab.Repository("/api/v4/projects/42/merge_requests/7/merge"))
	}
}
