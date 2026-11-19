package containers

import (
	"net/url"
	"testing"
)

func TestAuditBroker(t *testing.T) {
	c := testChecker()
	for _, tc := range []struct {
		name, method, path, query, body string
	}{
		{"volume o=bind on writable repo (non-recursive)", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"none","device":"/work","o":"bind"}}`},
		{"volume o=rbind on writable repo", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"none","device":"/work","o":"rbind"}}`},
		{"docker volume DriverOpts bind", "POST", "/volumes/create", "", `{"Name":"v","DriverOpts":{"type":"none","device":"/work","o":"bind"}}`},
		{"bind string non-recursive", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/work:/x:bind"]}}`},
		{"volume overlay lowerdir", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"overlay","device":"overlay","o":"lowerdir=/ro,upperdir=/work/up,workdir=/work/wk"}}`},
		{"volume overlay lowerdir outside", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"overlay","device":"overlay","o":"lowerdir=/etc"}}`},
		{"volume bind,ro,rw on ro path", "POST", "/libpod/volumes/create", "", `{"Name":"v","Options":{"type":"none","device":"/ro","o":"bind,ro,rw"}}`},
		{"bind ro,rw on ro path", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Binds":["/ro:/x:ro,rw"]}}`},
		{"libpod mount ro,rw", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"type":"bind","source":"/ro","destination":"/x","options":["ro","rw"]}]}`},
		{"libpod mount ro=false", "POST", "/libpod/containers/create", "", `{"image":"alpine","mounts":[{"type":"bind","source":"/ro","destination":"/x","options":["ro=false"]}]}`},
		{"libpod annotations", "POST", "/libpod/containers/create", "", `{"image":"alpine","annotations":{"run.oci.keep_original_groups":"1","org.systemd.property.DeviceAllow":"/dev/sda rw"}}`},
		{"docker annotations", "POST", "/containers/create", "", `{"Image":"alpine","HostConfig":{"Annotations":{"run.oci.handler":"krun"}}}`},
		{"libpod netns slirp allow_host_loopback", "POST", "/libpod/containers/create", "", `{"image":"alpine","netns":{"nsmode":"slirp4netns"},"network_options":{"slirp4netns":["allow_host_loopback=true"]}}`},
		{"libpod env_host", "POST", "/libpod/containers/create", "", `{"image":"alpine","env_host":true}`},
		{"libpod portmappings", "POST", "/libpod/containers/create", "", `{"image":"alpine","portmappings":[{"host_port":80,"container_port":80,"host_ip":"0.0.0.0"}]}`},
		{"build secret abs src", "POST", "/build", "secrets=%5B%22id%3Dx%2Csrc%3D%2Fetc%2Fshadow%22%5D", ""},
		{"build secret env", "POST", "/libpod/build", "secrets=%5B%22id%3Dx%2Cenv%3DHOME%22%5D", ""},
		{"build networkmode host", "POST", "/build", "networkmode=host", ""},
		{"build remote url", "POST", "/build", "remote=git%3A%2F%2Fevil%2Fx", ""},
		{"build extrahosts/ssh", "POST", "/libpod/build", "ssh=default", ""},
		{"build volume rw ro", "POST", "/libpod/build", "volume=%2Fro%3A%2Fx%3Aro%2Crw", ""},
		{"build ulimits cgroup", "POST", "/libpod/build", "cpuperiod=1&memory=1&t=docker.io%2Flibrary%2Falpine%3Alatest", ""},
		{"images load", "POST", "/images/load", "", ""},
		{"tag over allowed name", "POST", "/images/abc/tag", "repo=docker.io%2Flibrary%2Falpine&tag=latest", ""},
		{"commit", "POST", "/commit", "container=x&repo=docker.io%2Flibrary%2Falpine", ""},
		{"auth", "POST", "/auth", "", `{"serveraddress":"http://evil"}`},
		{"images search", "GET", "/images/search", "term=evil.example/x", ""},
		{"pull via /images/create fromSrc url", "POST", "/images/create", "fromSrc=http%3A%2F%2Fevil%2Fx.tar", ""},
		{"manifests", "POST", "/libpod/manifests/create", "", ""},
		{"generate systemd", "GET", "/libpod/generate/x/systemd", "", ""},
		{"double slash", "POST", "//containers/create", "", ""},
		{"versioned libpod", "POST", "/v5.0.0/libpod/containers/create", "", `{"image":"alpine","privileged":true}`},
		{"exec create privileged", "POST", "/containers/x/exec", "", `{"Privileged":true}`},
		{"exec libpod", "POST", "/libpod/containers/x/exec", "", `{"Privileged":true}`},
		{"container update", "POST", "/v1.41/containers/x/update", "", ""},
		{"libpod containers/x/update", "POST", "/libpod/containers/x/update", "", ""},
		{"pod create with userns host", "POST", "/libpod/pods/create", "", `{"userns":{"nsmode":"host"}}`},
		{"pod create share", "POST", "/libpod/pods/create", "", `{"share":"net,pid,ipc","pid":{"nsmode":"host"}}`},
		{"libpod volumes field", "POST", "/libpod/containers/create", "", `{"image":"alpine","volumes":[{"Name":"/etc","Dest":"/x"}]}`},
		{"cdi devices", "POST", "/libpod/containers/create", "", `{"image":"alpine","devices":[{"path":"vendor.com/gpu=0"}]}`},
		{"userns keep-id", "POST", "/libpod/containers/create", "", `{"image":"alpine","userns":{"nsmode":"keep-id"}}`},
		{"cap_drop/no_new_privileges false", "POST", "/libpod/containers/create", "", `{"image":"alpine","no_new_privileges":false}`},
		{"restart_policy always", "POST", "/libpod/containers/create", "", `{"image":"alpine","restart_policy":"always"}`},
		{"image_volumes with host", "POST", "/libpod/containers/create", "", `{"image":"alpine","image_volumes":[{"source":"alpine","destination":"/m"}]}`},
		{"hostadd/dns", "POST", "/libpod/containers/create", "", `{"image":"alpine","hostadd":["x:1.1.1.1"],"dns_server":["8.8.8.8"]}`},
		{"secrets with host path?", "POST", "/libpod/containers/create", "", `{"image":"alpine","secrets":[{"Source":"s","Target":"/x"}]}`},
		{"stop on update shared pod", "POST", "/libpod/pods/create", "", `{"infra_image":"docker.io/library/alpine"}`},
		{"system prune", "POST", "/libpod/system/prune", "", ""},
		{"events", "GET", "/events", "stream=true", ""},
	} {
		q, _ := url.ParseQuery(tc.query)
		p, ok := apiPath(tc.path)
		if !ok {
			t.Logf("%-50s => path refused", tc.name)
			continue
		}
		v := c.decide(request{Method: tc.method, Path: p, Query: q, Body: []byte(tc.body)})
		if v.refusal != "" {
			t.Logf("%-50s => REFUSED: %.90s", tc.name, v.refusal)
		} else {
			t.Logf("%-50s => ALLOWED ask=%v", tc.name, v.ask != nil)
		}
	}
}
