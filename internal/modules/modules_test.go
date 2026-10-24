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
	for _, name := range []string{"github", "gitlab", "forgejo", "bitbucket", "aws"} {
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
		{"POST", "/user/keys", "", "deny", ""},
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

func TestForgeModulesRefuseChangesToSecretsAndKeysButLetThemBeListed(t *testing.T) {
	body := "modules = [\"github\", \"gitlab\", \"forgejo\", \"bitbucket\"]\n"
	for _, name := range []string{"github", "gitlab", "forgejo", "bitbucket"} {
		body += "[secrets." + name + "]\ncommand = [\"true\"]\n"
	}
	l := &profile.Loader{Profiles: fstest.MapFS{"f.toml": {Data: []byte(body)}}, Modules: []fs.FS{FS}, Home: "/home/u"}
	p, err := l.Load("f")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ host, method, path, want string }{
		{"api.github.com", "PUT", "/repos/a/b/dependabot/secrets/X", "deny"},
		{"api.github.com", "PUT", "/repositories/1/dependabot/secrets/X", "deny"},
		{"api.github.com", "PUT", "/repos/a/b/codespaces/secrets/X", "deny"},
		{"api.github.com", "PUT", "/orgs/acme/actions/secrets/X", "deny"},
		{"api.github.com", "POST", "/orgs/acme/hooks", "deny"},
		{"api.github.com", "POST", "/repos/a/b/actions/variables", "approve"},
		{"api.github.com", "POST", "/user/keys", "deny"},
		{"api.github.com", "POST", "/user/gpg_keys", "deny"},
		{"api.github.com", "POST", "/user/ssh_signing_keys", "deny"},
		{"api.github.com", "GET", "/user/keys", "allow"},
		{"gitlab.com", "POST", "/api/v4/users/7/keys", "deny"},
		{"gitlab.com", "POST", "/api/v4/users/7/impersonation_tokens", "deny"},
		{"gitlab.com", "POST", "/api/v4/users/7/personal_access_tokens", "deny"},
		{"gitlab.com", "POST", "/api/v4/groups/acme/service_accounts/7/personal_access_tokens", "deny"},
		{"gitlab.com", "POST", "/api/v4/service_accounts", "deny"},
		{"gitlab.com", "PUT", "/api/v4/projects/42/approvals", "deny"},
		{"gitlab.com", "POST", "/api/v4/projects/42/approvals", "deny"},
		{"gitlab.com", "GET", "/api/v4/projects/42/approvals", "allow"},
		{"gitlab.com", "GET", "/api/v4/projects/42/secure_files/3/download", "deny"},
		{"gitlab.com", "GET", "/api/v4/projects/42/secure_files", "allow"},
		{"codeberg.org", "POST", "/api/v1/admin/users/x/keys", "deny"},
		{"codeberg.org", "GET", "/api/v1/admin/users", "allow"},
		{"api.bitbucket.org", "POST", "/2.0/users/x/ssh-keys", "deny"},
		{"api.bitbucket.org", "PUT", "/2.0/repositories/ws/repo/pipelines_config/ssh/key_pair", "deny"},
		{"api.bitbucket.org", "GET", "/2.0/users/x/ssh-keys", "allow"},
	} {
		h, ok := p.Intercepted(c.host)
		if !ok {
			t.Fatalf("%s is not inspected", c.host)
		}
		if r, _ := h.Decide(c.method, c.path, nil); string(r.Action) != c.want {
			t.Errorf("%s %s%s: %s, want %s", c.method, c.host, c.path, r.Action, c.want)
		}
	}
}

func TestTheAWSModuleRefusesWhatWouldBringCredentialsIntoTheJail(t *testing.T) {
	l := &profile.Loader{Profiles: fstest.MapFS{"a.toml": {Data: []byte("modules = [\"aws\"]\n[secrets.aws]\ncommand = [\"true\"]\n")}}, Modules: []fs.FS{FS}, Home: "/home/u"}
	p, err := l.Load("a")
	if err != nil {
		t.Fatal(err)
	}
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	target := func(v string) http.Header { return http.Header{"X-Amz-Target": {v}} }
	for _, c := range []struct {
		host, method, path string
		header             http.Header
		body, want         string
	}{
		{"sts.amazonaws.com", "POST", "/", form, "Action=GetCallerIdentity", "allow"},
		{"sts.us-east-1.amazonaws.com", "POST", "/", form, "Action=AssumeRole&RoleArn=x", "deny"},
		{"sts.amazonaws.com", "POST", "/", form, "Action=GetSessionToken", "deny"},
		{"portal.sso.eu-west-1.amazonaws.com", "GET", "/federation/credentials", http.Header{}, "", "deny"},
		{"api.ecr.us-east-1.amazonaws.com", "POST", "/", target("AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"), "", "deny"},
		{"secretsmanager.us-east-1.amazonaws.com", "POST", "/", target("secretsmanager.GetSecretValue"), "", "approve"},
		{"secretsmanager.us-east-1.amazonaws.com", "POST", "/", target("secretsmanager.BatchGetSecretValue"), "", "approve"},
		{"secretsmanager.us-east-1.amazonaws.com", "POST", "/", target("secretsmanager.ListSecrets"), "", "allow"},
		{"cloudformation.us-east-1.amazonaws.com", "POST", "/", form, "Action=DescribeStacks", "allow"},
		{"cloudformation.us-east-1.amazonaws.com", "POST", "/", form, "Action=DeleteStack", "approve"},
		{"dynamodb.us-east-1.amazonaws.com", "POST", "/", target("DynamoDB_20120810.Query"), "", "allow"},
		{"dynamodb.us-east-1.amazonaws.com", "POST", "/", target("DynamoDB_20120810.DeleteTable"), "", "approve"},
		{"my-bucket.s3.us-east-1.amazonaws.com", "GET", "/key", http.Header{}, "", "allow"},
		{"my-bucket.s3.us-east-1.amazonaws.com", "PUT", "/key", http.Header{}, "", "approve"},
		{"iam.amazonaws.com", "POST", "/", form, "Action=ListRoles", "allow"},
		{"iam.amazonaws.com", "POST", "/", form, "Action=CreateAccessKey", "deny"},
		{"iam.amazonaws.com", "POST", "/", form, "Action=AttachRolePolicy", "deny"},
		{"organizations.us-east-1.amazonaws.com", "POST", "/", target("AWSOrganizationsV20161128.InviteAccountToOrganization"), "", "deny"},
		{"iam-fips.amazonaws.com", "POST", "/", form, "Action=CreateAccessKey", "deny"},
		{"iam-fips.amazonaws.com", "POST", "/", form, "Action=ListRoles", "allow"},
		{"organizations-fips.us-east-1.amazonaws.com", "POST", "/", target("AWSOrganizationsV20161128.InviteAccountToOrganization"), "", "deny"},
		{"sts.amazonaws.com", "POST", "/", form, "Action=AssumeRoot", "deny"},
		{"redshift.us-east-1.amazonaws.com", "POST", "/", form, "Action=GetClusterCredentials", "deny"},
		{"redshift.us-east-1.amazonaws.com", "POST", "/", form, "Action=GetClusterCredentialsWithIAM", "deny"},
		{"redshift-serverless.us-east-1.amazonaws.com", "POST", "/", target("RedshiftServerless.GetCredentials"), "", "deny"},
		{"lightsail.us-east-1.amazonaws.com", "POST", "/", target("Lightsail_20161128.GetInstanceAccessDetails"), "", "deny"},
		{"lightsail.us-east-1.amazonaws.com", "POST", "/", target("Lightsail_20161128.GetRelationalDatabaseMasterUserPassword"), "", "deny"},
		{"gamelift.us-east-1.amazonaws.com", "POST", "/", target("GameLift.GetComputeAccess"), "", "deny"},
		{"gamelift.us-east-1.amazonaws.com", "POST", "/", target("GameLift.GetInstanceAccess"), "", "deny"},
		{"connect.us-east-1.amazonaws.com", "GET", "/user/federate/instance-id", http.Header{}, "", "deny"},
	} {
		h, ok := p.Intercepted(c.host)
		if !ok || h.Credential == nil || h.Credential.Scheme != profile.SchemeSigV4 {
			t.Fatalf("%s is not signed again: %+v", c.host, h)
		}
		if r, _ := h.DecideWithQuery(c.method, c.path, nil, c.header, []byte(c.body)); string(r.Action) != c.want {
			t.Errorf("%s %s%s %v %s: %s, want %s", c.method, c.host, c.path, c.header, c.body, r.Action, c.want)
		}
	}
}

func TestAKMSDataKeyWaitsWithItsOwnSummaryBecauseItCarriesAPlaintextKey(t *testing.T) {
	l := &profile.Loader{Profiles: fstest.MapFS{"a.toml": {Data: []byte("modules = [\"aws\"]\n[secrets.aws]\ncommand = [\"true\"]\n")}}, Modules: []fs.FS{FS}, Home: "/home/u"}
	p, err := l.Load("a")
	if err != nil {
		t.Fatal(err)
	}
	kms, _ := p.Intercepted("kms.us-east-1.amazonaws.com")
	r, _ := kms.DecideRequest("POST", "/", http.Header{"X-Amz-Target": {"TrentService.GenerateDataKey"}}, nil)
	if r.Action != profile.ActionApprove || r.Summary == "" {
		t.Errorf("GenerateDataKey = %v %q, want approve with a summary", r.Action, r.Summary)
	}
}

func TestAProfileNarrowsTheAWSHostsToItsRegion(t *testing.T) {
	body := "modules = [\"aws\"]\n[secrets.aws]\ncommand = [\"true\"]\n\n[[http]]\nhost = \"*.amazonaws.com\"\nonly = [\"sts.us-west-2.amazonaws.com\", \"*.s3.us-west-2.amazonaws.com\"]\n"
	l := &profile.Loader{Profiles: fstest.MapFS{"a.toml": {Data: []byte(body)}}, Modules: []fs.FS{FS}, Home: "/home/u"}
	p, err := l.Load("a")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"sts.us-west-2.amazonaws.com":             true,
		"my-bucket.s3.us-west-2.amazonaws.com":    true,
		"sts.us-east-1.amazonaws.com":             false,
		"their-bucket.s3.eu-west-1.amazonaws.com": false,
		"iam.amazonaws.com":                       true,
	} {
		h, ok := p.Intercepted(host)
		if ok != want || ok && h.Credential.Scheme != profile.SchemeSigV4 {
			t.Errorf("%s: intercepted %v, want %v", host, ok, want)
		}
		if p.AllowsHost(host) && !want {
			t.Errorf("%s is allowed outside the profile's hosts", host)
		}
	}
	for _, bad := range []string{"example.com", "*.com"} {
		body := "[[http]]\nhost = \"*.amazonaws.com\"\nonly = [\"" + bad + "\"]\n"
		if _, err := (&profile.Loader{Profiles: fstest.MapFS{"b.toml": {Data: []byte(body)}}, Home: "/home/u"}).Load("b"); err == nil {
			t.Errorf("only %q outside the host must be refused", bad)
		}
	}
}
