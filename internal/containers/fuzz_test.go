package containers

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"
	"testing"
)

var createPaths = []string{"/containers/create", "/libpod/containers/create", "/libpod/pods/create", "/containers/abc/exec"}

func FuzzCreate(f *testing.F) {
	for _, s := range []struct {
		api  uint8
		body string
	}{
		{0, `{"Image":"alpine"}`},
		{0, `{"Image":"alpine","HostConfig":{"Privileged":true}}`},
		{0, `{"Image":"alpine","HostConfig":{"Privileged":false,"privileged":true}}`},
		{0, `{"Image":"alpine","HostConfig":{"Privileged":false,"Privileged":true}}`},
		{0, `{"Image":"alpine","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`},
		{0, `{"Image":"alpine","HostConfig":{"PidMode":"host","IpcMode":"ns:/proc/1/ns/ipc","UsernsMode":"HOST"}}`},
		{0, `{"Image":"alpine","HostConfig":{"Binds":["/work/src:/src","/home/u/.ssh:/s"]}}`},
		{0, `{"Image":"alpine","HostConfig":{"Binds":["/work/../home/u:/s"]}}`},
		{0, `{"Image":"alpine","HostConfig":{"Binds":["/work/link:/s:ro"]}}`},
		{0, `{"Image":"alpine","HostConfig":{"Binds":["/work:/w"],"Bind\u017f":["/etc:/e"]}}`},
		{0, `{"Image":"alpine","HostConfig":{"Binds":["/etc:/e"],"Bind\u017f":["/work:/w"]}}`},
		{1, `{"image":"alpine","mounts":[{"destination":"/s","type":"bind","source":"/etc"}],"mount\u017f":[]}`},
		{0, `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/e","ReadOnly":true}]}}`},
		{0, `{"Image":"alpine","hostconfig":{"Mounts":[{"Source":"/work"}]},"HostConfig":{}}`},
		{1, `{"image":"alpine","privileged":true}`},
		{1, `{"image":"alpine","Cap_Add":["NET_ADMIN"]}`},
		{1, `{"image":"alpine","pidns":{"nsmode":"host"},"userns":{"nsmode":"path"}}`},
		{1, `{"image":"alpine","mounts":[{"destination":"/s","type":"none","source":"/etc","options":["bind"]}]}`},
		{1, `{"image":"alpine","mounts":[{"destination":"/w","type":"bind","source":"/work","options":["rbind"]}]}`},
		{2, `{"name":"p","pidns":{"nsmode":"host"}}`},
		{3, `{"Cmd":["sh"],"Privileged":true}`},
	} {
		f.Add(s.api, []byte(s.body))
	}
	c := testChecker()
	f.Fuzz(func(t *testing.T, api uint8, body []byte) {
		p := createPaths[int(api)%len(createPaths)]
		v := c.decide(request{Method: "POST", Path: p, Body: body})
		if v.refusal != "" {
			return
		}
		var doc map[string]any
		if json.Unmarshal(body, &doc) != nil {
			return
		}
		var reason string
		switch {
		case p == "/containers/create":
			reason = dockerViolation(c, doc)
		case strings.HasSuffix(p, "/exec"):
			if set(doc, "Privileged") {
				reason = "privileges"
			}
		default:
			reason = libpodViolation(c, doc)
		}
		if reason != "" {
			t.Fatalf("POST %s forwarded a body with %s: %s", p, reason, body)
		}
	})
}

func fields(doc map[string]any, field string) []any {
	var out []any
	for k, v := range doc {
		if strings.EqualFold(k, field) || strings.ToLower(k) == strings.ToLower(field) { //nolint:staticcheck // ToLower is what other decoders compare, and it differs from EqualFold for non-ASCII keys
			out = append(out, v)
		}
	}
	return out
}

func objects(doc map[string]any, field string) []map[string]any {
	var out []map[string]any
	for _, v := range fields(doc, field) {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func strs(doc map[string]any, field string) []string {
	var out []string
	for _, v := range fields(doc, field) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func set(doc map[string]any, field string) bool {
	for _, v := range fields(doc, field) {
		switch t := v.(type) {
		case bool:
			if t {
				return true
			}
		case []any:
			if len(t) > 0 {
				return true
			}
		}
	}
	return false
}

func outsideMounts(c checker, src string) bool {
	if !strings.HasPrefix(src, "/") {
		return false
	}
	resolved, _ := c.resolver.EvalSymlinks(path.Clean(src))
	for _, m := range c.policy.Mounts {
		if within(resolved, m.Path) {
			return false
		}
	}
	return true
}

func dockerViolation(c checker, doc map[string]any) string {
	for _, h := range objects(doc, "HostConfig") {
		if set(h, "Privileged") {
			return "privileges"
		}
		if set(h, "CapAdd") {
			return "added capabilities"
		}
		for _, ns := range []string{"PidMode", "IpcMode", "UsernsMode", "UTSMode", "CgroupnsMode"} {
			for _, mode := range strs(h, ns) {
				kind, _, _ := strings.Cut(strings.ToLower(mode), ":")
				if kind == "host" || kind == "ns" || kind == "path" {
					return "a host namespace"
				}
			}
		}
		for _, b := range strs(h, "Binds") {
			if src, _, ok := strings.Cut(b, ":"); ok && outsideMounts(c, src) {
				return "a bind outside the mounts"
			}
		}
		for _, list := range fields(h, "Mounts") {
			ms, _ := list.([]any)
			for _, raw := range ms {
				m, _ := raw.(map[string]any)
				types := strs(m, "Type")
				bind := len(types) == 0
				for _, typ := range types {
					bind = bind || strings.EqualFold(typ, "bind") || typ == ""
				}
				for _, src := range strs(m, "Source") {
					if bind && outsideMounts(c, src) {
						return "a mount outside the mounts"
					}
				}
			}
		}
	}
	return ""
}

func libpodViolation(c checker, doc map[string]any) string {
	if set(doc, "privileged") {
		return "privileges"
	}
	if set(doc, "cap_add") {
		return "added capabilities"
	}
	for _, ns := range []string{"pidns", "ipcns", "userns", "utsns", "cgroupns"} {
		for _, o := range objects(doc, ns) {
			for _, mode := range strs(o, "nsmode") {
				if strings.EqualFold(mode, "host") || strings.EqualFold(mode, "path") {
					return "a host namespace"
				}
			}
		}
	}
	for _, list := range fields(doc, "mounts") {
		ms, _ := list.([]any)
		for _, raw := range ms {
			m, _ := raw.(map[string]any)
			bind := false
			for _, typ := range strs(m, "type") {
				bind = bind || strings.EqualFold(typ, "bind")
			}
			for _, o := range strs(m, "options") {
				bind = bind || o == "bind" || o == "rbind"
			}
			for _, src := range strs(m, "source") {
				if bind && !strings.ContainsAny(src, "*?[") && outsideMounts(c, src) {
					return "a mount outside the mounts"
				}
			}
		}
	}
	return ""
}

func FuzzAPIPath(f *testing.F) {
	for _, s := range []string{
		"/v1.41/containers/json", "/v5.0.0/libpod/info", "/libpod/info", "/volumes/v1",
		"/v1.41/../plugins", "//containers/json", "/containers/json/", "/v1.41/libpod/containers/create",
		"/v1.41/", "/libpod/system/reset", "/v1.41/swarm/init",
	} {
		f.Add("POST", s, "", []byte(""))
	}
	f.Add("GET", "/images/docker.io/library/alpine/json", "", []byte(""))
	f.Add("POST", "/images/create", "fromImage=alpine&FromImage=quay.io/evil/miner", []byte(""))
	f.Add("POST", "/libpod/build", "volume=/home/u/.ssh:/s", []byte(""))
	f.Add("POST", "/volumes/create", "", []byte(`{"Name":"v","DriverOpts":{"o":"bind","device":"/home/u","type":"none"}}`))
	c := testChecker()
	f.Fuzz(func(t *testing.T, method, raw, query string, body []byte) {
		p, ok := apiPath(raw)
		if !ok {
			return
		}
		if !strings.HasPrefix(raw, "/") || path.Clean(raw) != raw || path.Clean(p) != p {
			t.Fatalf("apiPath accepted %q as %q", raw, p)
		}
		q, _ := url.ParseQuery(query)
		v := c.decide(request{Method: method, Path: p, Query: q, Body: body})
		if rt, ok := lookup(method, p); (!ok || rt.treat.refused != "") && v.refusal == "" {
			t.Fatalf("%s %s is not a forwarded endpoint and was let through", method, p)
		}
	})
}

var (
	refDomain = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*(?::[0-9]+)?`
	refPath   = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	reference = regexp.MustCompile(`^((?:` + refDomain + `/)?` + refPath + `(?:/` + refPath + `)*)(?::[\w][\w.-]{0,127})?(?:@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,})?$`)
)

func referenceRepo(ref string) (string, bool) {
	m := reference.FindStringSubmatch(ref)
	if m == nil {
		return "", false
	}
	name := m[1]
	domain, rest := "docker.io", name
	if i := strings.Index(name, "/"); i >= 0 {
		first := name[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" || strings.ToLower(first) != first {
			domain, rest = first, name[i+1:]
		}
	}
	if domain == "index.docker.io" {
		domain = "docker.io"
	}
	if domain == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return domain + "/" + rest, true
}

func FuzzImage(f *testing.F) {
	for _, s := range []string{
		"alpine", "alpine:3.20", "postgres@sha256:" + strings.Repeat("a", 64), "foo/bar", "docker.io/alpine",
		"index.docker.io/foo/bar:1", "localhost/app", "localhost:5000/app:2", "ghcr.io/acme/tool:1.2",
		"ghcr.io/acme/tool:1.3", "quay.io/evil/miner", "0123456789abcdef", "sha256:0123456789abcdef0123",
		"Docker.io/library/alpine", "docker.io/library/alpine/../../x", "evil.io/x@docker.io/library/alpine",
		" alpine ", "localhost", "docker.io/library/alpine:latest@sha256:" + strings.Repeat("b", 64),
	} {
		f.Add(s)
	}
	c := testChecker()
	f.Fuzz(func(t *testing.T, ref string) {
		r, normalized := normalizeImage(ref)
		if c.image(ref) == "" {
			if !normalized {
				t.Fatalf("image %q allowed without a name to check", ref)
			}
			if again, _ := normalizeImage(r.full); again != r {
				t.Fatalf("image %q normalizes to %+v, and that to %+v", ref, r, again)
			}
			if want, ok := referenceRepo(strings.TrimSpace(ref)); ok && want != r.repo {
				t.Fatalf("image %q allowed as %s, but the container tools read it as %s", ref, r.repo, want)
			}
		}
		if c.repository(ref) == "" {
			if want, ok := referenceRepo(strings.TrimSpace(ref)); ok && want != r.repo {
				t.Fatalf("repository %q allowed as %s, but the container tools read it as %s", ref, r.repo, want)
			}
		}
	})
}
