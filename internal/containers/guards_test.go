package containers

import (
	"net/url"
	"strings"
	"testing"
)

func TestGuardDecisions(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		query   string
		body    string
		refused string
	}{
		{"libpod-only route at the docker path", "POST", "/containers/abc/init", "", "", "not an endpoint"},
		{"libpod-only route", "POST", "/libpod/containers/abc/init", "", "", ""},

		{"docker import from file URL", "POST", "/images/create", "fromSrc=file://host/etc/shadow", "", "importing"},
		{"libpod import over ftp", "POST", "/libpod/images/import", "url=ftp://example.com/x.tar", "", "importing"},
		{"libpod import from https without host", "POST", "/libpod/images/import", "url=https:///x.tar", "", "importing"},

		{"build caps after an empty list", "POST", "/libpod/build", "addcaps=%5B%5D&addcaps=SYS_ADMIN", "", "addcaps"},
		{"build ns private pid", "POST", "/libpod/build", "nsoptions=%5B%7B%22Name%22%3A%22pid%22%2C%22Host%22%3Afalse%7D%5D", "", ""},
		{"build secret inside context", "POST", "/libpod/build", "secrets=%5B%22id%3Da%2Csrc%3Dsub%2Ffile%22%5D", "", ""},
		{"build context url", "POST", "/libpod/build", "additionalbuildcontexts=a%3Durl%3Ahttps%3A%2F%2Fexample.com%2Fctx.tar", "", ""},
		{"build context image", "POST", "/libpod/build", "additionalbuildcontexts=a%3Dimage%3Adocker.io%2Flibrary%2Falpine", "", ""},

		{"docker secret file driver", "POST", "/secrets/create", "", `{"Name":"s","Data":"eA==","Driver":{"Name":"file"}}`, ""},
		{"docker secret file driver options", "POST", "/secrets/create", "", `{"Name":"s","Data":"eA==","Driver":{"Name":"file","Options":{"path":"/etc"}}}`, "options"},
		{"libpod secret empty driver options", "POST", "/libpod/secrets/create", "name=s&driveropts=%7B%7D", "", ""},
		{"libpod secret options after empty ones", "POST", "/libpod/secrets/create", "name=s&driveropts=%7B%7D&driveropts=%7B%22path%22%3A%22%2Fetc%22%7D", "", "options"},
		{"libpod secret unparsable driver options", "POST", "/libpod/secrets/create", "name=s&driveropts=path%3D%2Fetc", "", "options"},

		{"create named volume mount", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"data","Target":"/d"}]}}`, ""},
		{"libpod tmpfs mount with rbind", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/s","type":"tmpfs","source":"/etc","options":["rbind"]}]}`, "outside the mounts"},
		{"non-recursive bind beside read-only mounts", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work/src:/w:bind"]}}`, ""},
	}
	c := testChecker()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := url.ParseQuery(tt.query)
			if err != nil {
				t.Fatal(err)
			}
			v := c.decide(request{Method: tt.method, Path: tt.path, Query: q, Body: []byte(tt.body)})
			switch {
			case tt.refused == "" && v.refusal != "":
				t.Fatalf("refused: %s", v.refusal)
			case tt.refused != "" && !strings.Contains(v.refusal, tt.refused):
				t.Fatalf("refusal %q does not contain %q", v.refusal, tt.refused)
			}
		})
	}
}

func TestWithTag(t *testing.T) {
	tests := []struct{ ref, tag, want string }{
		{"docker.io/library/alpine", "", "docker.io/library/alpine"},
		{"docker.io/library/alpine", "3.20", "docker.io/library/alpine:3.20"},
		{"docker.io/library/alpine:3.19", "3.20", "docker.io/library/alpine:3.19"},
		{"docker.io/library/alpine@sha256:abc", "3.20", "docker.io/library/alpine@sha256:abc"},
		{"docker.io/library/alpine", "sha256:abc", "docker.io/library/alpine@sha256:abc"},
		{"localhost:5000/app", "1", "localhost:5000/app:1"},
	}
	for _, tt := range tests {
		if got := withTag(tt.ref, tt.tag); got != tt.want {
			t.Errorf("withTag(%q, %q) = %q, want %q", tt.ref, tt.tag, got, tt.want)
		}
	}
}

func TestNonRecursiveBindOverWritableMountsAllowed(t *testing.T) {
	c := checker{policy: Policy{Mounts: []Mount{{Path: "/a"}, {Path: "/a/b"}}}, profile: "dev"}
	if reason := c.bindArgument("/a:/x:bind"); reason != "" {
		t.Fatalf("refused: %s", reason)
	}
}
