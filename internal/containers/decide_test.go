package containers

import (
	"net/url"
	"strings"
	"testing"
)

// links resolves symbolic links from a fixed table.
type links map[string]string

func (l links) EvalSymlinks(p string) (string, error) {
	for from, to := range l {
		if within(p, from) {
			return to + strings.TrimPrefix(p, from), nil
		}
	}
	return p, nil
}

func testChecker() checker {
	return checker{
		policy: Policy{
			Images: []string{"docker.io/library/*", "localhost/*", "ghcr.io/acme/tool:1.2"},
			Mounts: []Mount{
				{Path: "/work"},
				{Path: "/work/.git/hooks", ReadOnly: true},
				{Path: "/ro", ReadOnly: true},
			},
		},
		resolver: links{"/work/link": "/home/u/.ssh"},
		profile:  "dev",
	}
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		query  string
		body   string
		// refused is a substring of the refusal, or empty when allowed.
		refused string
	}{
		{"ping", "GET", "/_ping", "", "", ""},
		{"libpod ping head", "HEAD", "/libpod/_ping", "", "", ""},
		{"container list", "GET", "/containers/json", "", "", ""},
		{"unknown endpoint", "POST", "/plugins/pull", "", "", "plugins"},
		{"unlisted endpoint", "GET", "/session", "", "", "not an endpoint"},
		{"wrong method", "DELETE", "/info", "", "", "not an endpoint"},
		{"play kube", "POST", "/libpod/play/kube", "", "", "kube YAML"},
		{"kube play", "POST", "/libpod/kube/play", "", "", "kube YAML"},
		{"renumber", "POST", "/libpod/system/renumber", "", "", "not allowed"},
		{"local build", "POST", "/libpod/local/build", "", "", "service's side"},
		{"swarm", "POST", "/swarm/init", "", "", "swarm"},
		{"image inspect with slashes", "GET", "/images/docker.io/library/alpine/json", "", "", ""},
		{"libpod image remove", "DELETE", "/libpod/images/docker.io/library/alpine:3", "", "", ""},
		{"attach", "POST", "/containers/abc/attach", "", "", ""},
		{"archive put", "PUT", "/libpod/containers/abc/archive", "", "", ""},
		{"update", "POST", "/containers/abc/update", "", "", "devices"},

		{"create plain", "POST", "/containers/create", "", `{"Image":"alpine"}`, ""},
		{"create privileged", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Privileged":true}}`, "privileged containers"},
		{"create cap add", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, "capabilities"},
		{"create devices", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/kvm"}]}}`, "devices"},
		{"create device requests", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"DeviceRequests":[{"Count":-1}]}}`, "device requests"},
		{"create bind allowed", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work/src:/src"]}}`, ""},
		{"create bind outside", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/home/u/.ssh:/s"]}}`, "outside the mounts"},
		{"create bind dotdot", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work/../home/u:/s"]}}`, "outside the mounts"},
		{"create bind string prefix", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/workspace:/s"]}}`, "outside the mounts"},
		{"create bind symlink", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work/link:/s:ro"]}}`, "outside the mounts"},
		{"create bind relative", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["./x:/s"]}}`, "neither"},
		{"create named volume", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["data:/data"]}}`, ""},
		{"create bind read-only mount writable", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/ro/x:/x"]}}`, "read-only in profile"},
		{"create bind read-only mount ro", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/ro/x:/x:ro,z"]}}`, ""},
		{"create bind overlay on read-only", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/ro:/x:O"]}}`, ""},
		{"create bind chown on read-only", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/ro:/x:ro,U"]}}`, "read-only in profile"},
		{"create bind nested read-only", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work/.git/hooks:/h"]}}`, "read-only in profile"},
		{"create non-recursive bind uncovers", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work:/w:bind"]}}`, "uncover"},
		{"create recursive bind", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work:/w:rbind"]}}`, ""},
		{"create mount bind outside", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/e","ReadOnly":true}]}}`, "outside the mounts"},
		{"create mount non-recursive", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/work","Target":"/w","BindOptions":{"NonRecursive":true}}]}}`, "uncover"},
		{"create mount volume bind driver", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Target":"/w","VolumeOptions":{"DriverConfig":{"Options":{"o":"bind","device":"/etc"}}}}]}}`, "outside the mounts"},
		{"create mount tmpfs", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t"}]}}`, ""},
		{"create volumes from", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"VolumesFrom":["other"]}}`, "volumes from"},
		{"create pid host", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"PidMode":"host"}}`, "host's pid"},
		{"create userns host", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"UsernsMode":"host"}}`, "host's user"},
		{"create cgroupns host", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"CgroupnsMode":"host"}}`, "host's cgroup"},
		{"create ipc ns path", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"IpcMode":"ns:/proc/1/ns/ipc"}}`, "by path"},
		{"create network host", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}`, ""},
		{"create pid container", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"PidMode":"container:abc"}}`, ""},
		{"create seccomp unconfined", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, "seccomp"},
		{"create seccomp colon", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"SecurityOpt":["seccomp:unconfined"]}}`, "seccomp"},
		{"create apparmor unconfined", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`, "AppArmor"},
		{"create label disable", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"SecurityOpt":["label=disable"]}}`, "SELinux"},
		{"create no new privileges false", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"SecurityOpt":["no-new-privileges=false"]}}`, "no-new-privileges"},
		{"create no new privileges", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"SecurityOpt":["no-new-privileges"]}}`, ""},
		{"create runtime", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Runtime":"crun-vm"}}`, "OCI runtime"},
		{"create sysctls", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Sysctls":{"kernel.x":"1"}}}`, "sysctls"},
		{"create cgroup parent", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"CgroupParent":"/x"}}`, "cgroup parent"},
		{"create log path", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"LogConfig":{"Type":"k8s-file","Config":{"path":"/home/u/.bashrc"}}}}`, "log path"},
		{"create image not allowed", "POST", "/containers/create", "", `{"Image":"quay.io/evil/miner"}`, "[podman] images"},
		{"create image allowed tag", "POST", "/containers/create", "", `{"Image":"ghcr.io/acme/tool:1.2"}`, ""},
		{"create image other tag", "POST", "/containers/create", "", `{"Image":"ghcr.io/acme/tool:1.3"}`, "[podman] images"},
		{"create image by id", "POST", "/containers/create", "", `{"Image":"0123456789abcdef"}`, "by name"},
		{"create duplicate key", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Privileged":false,"privileged":true}}`, "twice"},
		{"create bad json", "POST", "/containers/create", "", `{"Image":`, "cannot be checked"},
		{"create versioned", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Privileged":true}}`, "privileged"},

		{"libpod create plain", "POST", "/libpod/containers/create", "", `{"image":"alpine","netns":{"nsmode":"host"}}`, ""},
		{"libpod privileged", "POST", "/libpod/containers/create", "", `{"image":"alpine","privileged":true}`, "privileged containers"},
		{"libpod cap add", "POST", "/libpod/containers/create", "", `{"image":"alpine","cap_add":["NET_ADMIN"]}`, "capabilities"},
		{"libpod devices", "POST", "/libpod/containers/create", "", `{"image":"alpine","devices":[{"path":"/dev/fuse"}]}`, "devices"},
		{"libpod pidns host", "POST", "/libpod/containers/create", "", `{"image":"alpine","pidns":{"nsmode":"host"}}`, "host's pid"},
		{"libpod userns host", "POST", "/libpod/containers/create", "", `{"image":"alpine","userns":{"nsmode":"host"}}`, "host's user"},
		{"libpod utsns path", "POST", "/libpod/containers/create", "", `{"image":"alpine","utsns":{"nsmode":"path","value":"/proc/1/ns/uts"}}`, "by path"},
		{"libpod mount bind allowed", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/w","type":"bind","source":"/work","options":["rbind"]}]}`, ""},
		{"libpod mount bind outside", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/s","type":"bind","source":"/home/u/.ssh","options":["rbind","ro"]}]}`, "outside the mounts"},
		{"libpod mount bind read-only", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/r","type":"bind","source":"/ro","options":["rbind"]}]}`, "read-only in profile"},
		{"libpod mount bind read-only ro", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/r","type":"bind","source":"/ro","options":["rbind","ro"]}]}`, ""},
		{"libpod mount bind by option", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/s","type":"none","source":"/etc","options":["bind"]}]}`, "outside the mounts"},
		{"libpod mount proc", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"destination":"/p","type":"proc","source":"proc"}]}`, "type \"proc\""},
		{"libpod named volume", "POST", "/libpod/containers/create", "", `{"image":"alpine","volumes":[{"Name":"data","Dest":"/d"}]}`, ""},
		{"libpod overlay outside", "POST", "/libpod/containers/create", "", `{"image":"alpine","overlay_volumes":[{"destination":"/o","source":"/etc"}]}`, "outside the mounts"},
		{"libpod overlay on read-only", "POST", "/libpod/containers/create", "", `{"image":"alpine","overlay_volumes":[{"destination":"/o","source":"/ro"}]}`, ""},
		{"libpod overlay upperdir", "POST", "/libpod/containers/create", "", `{"image":"alpine","overlay_volumes":[{"destination":"/o","source":"/work","options":["upperdir=/etc"]}]}`, "upperdir"},
		{"libpod volumes from", "POST", "/libpod/containers/create", "", `{"image":"alpine","volumes_from":["x"]}`, "volumes from"},
		{"libpod rootfs", "POST", "/libpod/containers/create", "", `{"rootfs":"/"}`, "rootfs"},
		{"libpod oci runtime", "POST", "/libpod/containers/create", "", `{"image":"alpine","oci_runtime":"/tmp/x"}`, "OCI runtime"},
		{"libpod seccomp unconfined", "POST", "/libpod/containers/create", "", `{"image":"alpine","seccomp_profile_path":"unconfined"}`, "seccomp"},
		{"libpod seccomp image", "POST", "/libpod/containers/create", "", `{"image":"alpine","seccomp_policy":"image"}`, "seccomp"},
		{"libpod apparmor unconfined", "POST", "/libpod/containers/create", "", `{"image":"alpine","apparmor_profile":"unconfined"}`, "AppArmor"},
		{"libpod selinux disable", "POST", "/libpod/containers/create", "", `{"image":"alpine","selinux_opts":["disable"]}`, "SELinux"},
		{"libpod sysctl", "POST", "/libpod/containers/create", "", `{"image":"alpine","sysctl":{"net.x":"1"}}`, "sysctls"},
		{"libpod init path", "POST", "/libpod/containers/create", "", `{"image":"alpine","init_path":"/home/u/bin/x"}`, "init binary"},
		{"libpod unmask", "POST", "/libpod/containers/create", "", `{"image":"alpine","unmask":["ALL"]}`, "unmasked"},
		{"libpod hosts file outside", "POST", "/libpod/containers/create", "", `{"image":"alpine","base_hosts_file":"/home/u/.netrc"}`, "outside the mounts"},
		{"libpod hosts file image", "POST", "/libpod/containers/create", "", `{"image":"alpine","base_hosts_file":"image"}`, ""},
		{"libpod hostadd", "POST", "/libpod/containers/create", "", `{"image":"alpine","hostadd":["x:127.0.0.1"]}`, ""},
		{"libpod image not allowed", "POST", "/libpod/containers/create", "", `{"image":"quay.io/evil/miner:latest"}`, "[podman] images"},
		{"libpod unknown field", "POST", "/libpod/containers/create", "", `{"image":"alpine","something_new":{"a":1}}`, ""},
		{"libpod too clever case", "POST", "/libpod/containers/create", "", `{"image":"alpine","Privileged":true}`, "privileged"},

		{"pod create plain", "POST", "/libpod/pods/create", "", `{"name":"p"}`, ""},
		{"pod create pid host", "POST", "/libpod/pods/create", "", `{"name":"p","pidns":{"nsmode":"host"}}`, "host's pid"},
		{"pod create devices", "POST", "/libpod/pods/create", "", `{"name":"p","pod_devices":["/dev/kvm"]}`, "devices"},
		{"pod create infra image", "POST", "/libpod/pods/create", "", `{"name":"p","infra_image":"quay.io/evil/pause"}`, "[podman] images"},
		{"pod create security opt", "POST", "/libpod/pods/create", "", `{"name":"p","security_opt":["seccomp=unconfined"]}`, "seccomp"},

		{"exec create", "POST", "/containers/abc/exec", "", `{"Cmd":["sh"]}`, ""},
		{"exec privileged", "POST", "/libpod/containers/abc/exec", "", `{"Cmd":["sh"],"Privileged":true}`, "privileged exec"},

		{"docker pull allowed", "POST", "/images/create", "fromImage=alpine&tag=3.20", "", ""},
		{"docker pull refused", "POST", "/images/create", "fromImage=quay.io/evil/miner&tag=latest", "", "quay.io/evil/miner:latest"},
		{"docker pull digest tag", "POST", "/images/create", "fromImage=quay.io/evil/miner&tag=sha256:abc", "", "quay.io/evil/miner@sha256:abc"},
		{"docker pull case", "POST", "/images/create", "FromImage=quay.io/evil/miner", "", "[podman] images"},
		{"docker import file", "POST", "/images/create", "fromSrc=/home/u/.ssh/id_ed25519", "", "importing"},
		{"docker import body", "POST", "/images/create", "fromSrc=-&repo=x", "", ""},
		{"libpod pull allowed", "POST", "/libpod/images/pull", "reference=docker.io/library/alpine:latest", "", ""},
		{"libpod pull refused", "POST", "/libpod/images/pull", "reference=quay.io/evil/miner", "", "[podman] images"},
		{"libpod pull all tags", "POST", "/libpod/images/pull", "reference=ghcr.io/acme/tool&allTags=true", "", "every tag"},
		{"libpod import path", "POST", "/libpod/images/import", "URL=/etc/shadow", "", "importing"},
		{"libpod import url", "POST", "/libpod/images/import", "url=https://example.com/x.tar", "", ""},

		{"volume create", "POST", "/volumes/create", "", `{"Name":"v"}`, ""},
		{"volume bind outside", "POST", "/volumes/create", "", `{"Name":"v","DriverOpts":{"o":"bind","device":"/home/u","type":"none"}}`, "outside the mounts"},
		{"volume bind allowed", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"o":"bind","device":"/work/cache"}}`, ""},
		{"volume bind read-only", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"o":"bind","device":"/ro"}}`, "read-only in profile"},
		{"volume block device", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"ext4","device":"/dev/sda1"}}`, "device /dev/sda1"},
		{"volume tmpfs", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"tmpfs","device":"tmpfs","o":"size=1m"}}`, ""},
		{"volume plugin driver", "POST", "/volumes/create", "", `{"Name":"v","Driver":"sshfs"}`, "volume driver"},

		{"build plain", "POST", "/libpod/build", "t=x&dockerfile=%5B%22Containerfile%22%5D&isolation=0&networkmode=0", "", ""},
		{"build docker", "POST", "/build", "t=x&dockerfile=Dockerfile", "", ""},
		{"build securityopt", "POST", "/build", "securityopt=%5B%22seccomp%3Dunconfined%22%5D", "", "seccomp"},
		{"build caps", "POST", "/libpod/build", "addcaps=%5B%22SYS_ADMIN%22%5D", "", "addcaps"},
		{"build volume outside", "POST", "/libpod/build", "volume=/home/u/.ssh:/s", "", "outside the mounts"},
		{"build volume allowed", "POST", "/libpod/build", "volume=/work:/w:ro", "", ""},
		{"build dockerfile absolute", "POST", "/libpod/build", "dockerfile=%5B%22%2Fetc%2Fshadow%22%5D", "", "build context"},
		{"build dockerfile escapes", "POST", "/libpod/build", "dockerfile=..%2F..%2Fx", "", "build context"},
		{"build secret escapes", "POST", "/libpod/build", "secrets=%5B%22id%3Da%2Csrc%3D..%2F..%2F..%2Fhome%2Fu%2F.ssh%2Fid%22%5D", "", "secret"},
		{"build isolation chroot", "POST", "/libpod/build", "isolation=2", "", "isolation"},
		{"build ns host", "POST", "/libpod/build", "nsoptions=%5B%7B%22Name%22%3A%22pid%22%2C%22Host%22%3Atrue%7D%5D", "", "host's pid"},
		{"build ns network host", "POST", "/libpod/build", "nsoptions=%5B%7B%22Name%22%3A%22network%22%2C%22Host%22%3Atrue%7D%5D", "", ""},
		{"build local context", "POST", "/libpod/build", "additionalbuildcontexts=a%3Dlocalpath%3A%2Fetc", "", "build context"},
		{"build rusage file", "POST", "/libpod/build", "rusagelogfile=/home/u/.bashrc", "", "rusagelogfile"},

		{"secret create", "POST", "/libpod/secrets/create", "name=s", "", ""},
		{"secret shell driver", "POST", "/libpod/secrets/create", "name=s&driver=shell", "", "secret driver"},
		{"secret driver opts", "POST", "/libpod/secrets/create", "name=s&driveropts=%7B%22path%22%3A%22%2Fetc%22%7D", "", "options"},
		{"docker secret driver", "POST", "/secrets/create", "", `{"Name":"s","Data":"eA==","Driver":{"Name":"pass"}}`, "secret driver"},
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

func TestPushAsks(t *testing.T) {
	tests := []struct {
		path, query, summary, scope string
	}{
		{"/images/docker.io/acme/app/push", "tag=v1", "Push container image docker.io/acme/app to docker.io/acme/app:v1", "containers push docker.io/acme/app:v1"},
		{"/libpod/images/localhost/app:1/push", "destination=ghcr.io/acme/app:1", "Push container image localhost/app:1 to ghcr.io/acme/app:1", "containers push ghcr.io/acme/app:1"},
		{"/libpod/images/ghcr.io/acme/app:1/push", "", "Push container image ghcr.io/acme/app:1", "containers push ghcr.io/acme/app:1"},
	}
	for _, tt := range tests {
		q, _ := url.ParseQuery(tt.query)
		v := testChecker().decide(request{Method: "POST", Path: tt.path, Query: q})
		if v.ask == nil {
			t.Fatalf("%s: no approval asked: %+v", tt.path, v)
		}
		if v.ask.summary != tt.summary || v.ask.scope != tt.scope {
			t.Errorf("%s: got %q / %q", tt.path, v.ask.summary, v.ask.scope)
		}
	}
}

func TestEmptyImagePolicyAllowsAny(t *testing.T) {
	c := checker{}
	v := c.decide(request{Method: "POST", Path: "/libpod/images/pull", Query: url.Values{"reference": {"quay.io/any/thing"}}})
	if v.refusal != "" {
		t.Fatal(v.refusal)
	}
}

func TestRefusalsNameTheSetting(t *testing.T) {
	c := testChecker()
	v := c.decide(request{Method: "POST", Path: "/containers/create", Body: []byte(`{"Image":"alpine","HostConfig":{"Binds":["/home/u/.ssh:/s"]}}`)})
	for _, want := range []string{"/home/u/.ssh", `profile "dev"`, "[[mounts]]"} {
		if !strings.Contains(v.refusal, want) {
			t.Errorf("refusal %q lacks %q", v.refusal, want)
		}
	}
}

func TestNormalizeImage(t *testing.T) {
	tests := []struct{ in, full, repo string }{
		{"alpine", "docker.io/library/alpine:latest", "docker.io/library/alpine"},
		{"alpine:3.20", "docker.io/library/alpine:3.20", "docker.io/library/alpine"},
		{"foo/bar", "docker.io/foo/bar:latest", "docker.io/foo/bar"},
		{"docker.io/alpine", "docker.io/library/alpine:latest", "docker.io/library/alpine"},
		{"index.docker.io/foo/bar:1", "docker.io/foo/bar:1", "docker.io/foo/bar"},
		{"localhost/app", "localhost/app:latest", "localhost/app"},
		{"localhost:5000/app:2", "localhost:5000/app:2", "localhost:5000/app"},
		{"ghcr.io/a/b@sha256:abc", "ghcr.io/a/b@sha256:abc", "ghcr.io/a/b"},
		{"ghcr.io/a/b:1@sha256:abc", "ghcr.io/a/b:1@sha256:abc", "ghcr.io/a/b"},
	}
	for _, tt := range tests {
		full, repo, ok := normalizeImage(tt.in)
		if !ok || full != tt.full || repo != tt.repo {
			t.Errorf("normalizeImage(%q) = %q, %q, %v; want %q, %q", tt.in, full, repo, ok, tt.full, tt.repo)
		}
	}
	if _, _, ok := normalizeImage("sha256:0123456789abcdef0123"); ok {
		t.Error("an image ID normalized")
	}
}

func TestAPIPath(t *testing.T) {
	tests := []struct {
		in, out string
		ok      bool
	}{
		{"/v1.41/containers/json", "/containers/json", true},
		{"/v5.0.0/libpod/info", "/libpod/info", true},
		{"/libpod/info", "/libpod/info", true},
		{"/volumes/v1", "/volumes/v1", true},
		{"/v1.41/../plugins", "", false},
		{"//containers/json", "", false},
		{"/containers/json/", "", false},
	}
	for _, tt := range tests {
		out, ok := apiPath(tt.in)
		if out != tt.out || ok != tt.ok {
			t.Errorf("apiPath(%q) = %q, %v", tt.in, out, ok)
		}
	}
}

func TestResolveMissingPath(t *testing.T) {
	c := checker{resolver: missing{links: links{"/work/link": "/home/u"}, exists: "/work/link"}}
	if got := c.resolve("/work/link/new/dir"); got != "/home/u/new/dir" {
		t.Fatalf("got %s", got)
	}
}

// missing resolves only paths up to exists, like a file system where the rest
// is not created yet.
type missing struct {
	links  links
	exists string
}

func (m missing) EvalSymlinks(p string) (string, error) {
	if !within(m.exists, p) {
		return "", errNotBind
	}
	return m.links.EvalSymlinks(p)
}
