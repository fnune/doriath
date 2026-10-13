package containers

import (
	"path"
	"regexp"
	"strings"
)

// api says which of podman's two APIs a route belongs to. Libpod routes are
// the same paths under /libpod.
type api int

const (
	docker api = 1 << iota
	libpod
	both = docker | libpod
)

// treatment is what the broker does with requests to a route.
type treatment struct {
	// refused, when set, says why the route is never forwarded.
	refused string
	check   func(checker, request) verdict
	body    bool
	stream  bool
}

var allowed = treatment{}

// streamed routes switch the connection to a raw stream, with a 101 response
// or, for older clients, a 200 response without a length.
var streamed = treatment{stream: true}

func refused(reason string) treatment { return treatment{refused: reason} }

func onQuery(f func(checker, request) verdict) treatment { return treatment{check: f} }

func onBody(f func(checker, request) verdict) treatment { return treatment{check: f, body: true} }

type route struct {
	api     api
	methods string
	// pattern segments: * matches one segment, ** one or more, for image
	// names such as docker.io/library/alpine.
	pattern string
	treat   treatment
}

// routes lists every endpoint that reaches podman. The first match wins and
// anything else is refused.
var routes = expand([]route{
	{both, "GET HEAD", "/_ping", allowed},
	{both, "GET", "/version", allowed},
	{both, "GET", "/info", allowed},
	{both, "GET", "/events", allowed},
	{both, "POST", "/auth", allowed},
	{both, "GET", "/system/df", allowed},
	{libpod, "POST", "/system/prune", allowed},
	{libpod, "*", "/system/renumber", refused("it rewrites the lock numbers of every container")},
	{libpod, "*", "/system/migrate", refused("it migrates every container to a new runtime")},
	{libpod, "*", "/system/reset", refused("it removes all podman state")},

	{both, "GET", "/containers/json", allowed},
	{docker, "POST", "/containers/create", onBody(dockerCreate)},
	{libpod, "POST", "/containers/create", onBody(libpodCreate)},
	{libpod, "GET", "/containers/stats", allowed},
	{both, "POST", "/containers/prune", allowed},
	{both, "GET", "/containers/*/json", allowed},
	{libpod, "GET", "/containers/*/exists", allowed},
	{libpod, "GET", "/containers/*/healthcheck", allowed},
	{both, "POST", "/containers/*/start", allowed},
	{both, "POST", "/containers/*/stop", allowed},
	{both, "POST", "/containers/*/restart", allowed},
	{both, "POST", "/containers/*/kill", allowed},
	{both, "POST", "/containers/*/pause", allowed},
	{both, "POST", "/containers/*/unpause", allowed},
	{both, "POST", "/containers/*/wait", allowed},
	{both, "POST", "/containers/*/rename", allowed},
	{libpod, "POST", "/containers/*/init", allowed},
	{both, "DELETE", "/containers/*", allowed},
	{both, "GET", "/containers/*/logs", allowed},
	{both, "POST", "/containers/*/attach", streamed},
	{both, "POST", "/containers/*/resize", allowed},
	{both, "GET", "/containers/*/top", allowed},
	{both, "GET", "/containers/*/stats", allowed},
	{both, "GET", "/containers/*/changes", allowed},
	{both, "GET HEAD PUT", "/containers/*/archive", allowed},
	{both, "GET", "/containers/*/export", allowed},
	{both, "POST", "/containers/*/exec", onBody(execCreate)},
	{both, "*", "/containers/*/update", refused("it can add devices to a running container")},
	{libpod, "*", "/containers/*/mount", refused("it mounts a container's files where only the podman service sees them")},
	{libpod, "*", "/containers/*/checkpoint", refused("checkpoints need privileges that containers do not get")},
	{libpod, "*", "/containers/*/restore", refused("checkpoints need privileges that containers do not get")},
	{both, "POST", "/commit", allowed},

	{both, "POST", "/exec/*/start", streamed},
	{both, "POST", "/exec/*/resize", allowed},
	{both, "GET", "/exec/*/json", allowed},
	{libpod, "POST", "/exec/*/remove", allowed},

	{both, "GET", "/images/json", allowed},
	{docker, "POST", "/images/create", onQuery(dockerPull)},
	{libpod, "POST", "/images/pull", onQuery(libpodPull)},
	{both, "GET", "/images/search", allowed},
	{both, "POST", "/images/prune", allowed},
	{both, "POST", "/images/load", allowed},
	{docker, "GET", "/images/get", allowed},
	{libpod, "GET", "/images/export", allowed},
	{libpod, "POST", "/images/import", onQuery(libpodImport)},
	{libpod, "DELETE", "/images/remove", allowed},
	{libpod, "*", "/images/scp/**", refused("it copies images to other hosts over SSH")},
	{both, "POST", "/images/**/push", onQuery(push)},
	{both, "GET", "/images/**/json", allowed},
	{both, "GET", "/images/**/history", allowed},
	{both, "GET", "/images/**/get", allowed},
	{both, "POST", "/images/**/tag", allowed},
	{libpod, "POST", "/images/**/untag", allowed},
	{libpod, "GET", "/images/**/exists", allowed},
	{libpod, "GET", "/images/**/tree", allowed},
	{libpod, "GET", "/images/**/resolve", allowed},
	{libpod, "GET", "/images/**/changes", allowed},
	{both, "DELETE", "/images/**", allowed},
	{docker, "POST", "/build", onQuery(build)},
	{libpod, "POST", "/build", onQuery(build)},
	{libpod, "*", "/local/**", refused("it reads paths on the podman service's side directly")},

	{docker, "GET", "/volumes", allowed},
	{libpod, "GET", "/volumes/json", allowed},
	{both, "POST", "/volumes/create", onBody(volumeCreate)},
	{both, "POST", "/volumes/prune", allowed},
	{docker, "GET", "/volumes/*", allowed},
	{libpod, "GET", "/volumes/*/json", allowed},
	{libpod, "GET", "/volumes/*/exists", allowed},
	{libpod, "GET", "/volumes/*/export", allowed},
	{libpod, "POST", "/volumes/*/import", allowed},
	{both, "DELETE", "/volumes/*", allowed},

	{docker, "GET", "/networks", allowed},
	{libpod, "GET", "/networks/json", allowed},
	{both, "POST", "/networks/create", allowed},
	{both, "POST", "/networks/prune", allowed},
	{docker, "GET", "/networks/*", allowed},
	{libpod, "GET", "/networks/*/json", allowed},
	{libpod, "GET", "/networks/*/exists", allowed},
	{both, "POST", "/networks/*/connect", allowed},
	{both, "POST", "/networks/*/disconnect", allowed},
	{libpod, "POST", "/networks/*/update", allowed},
	{both, "DELETE", "/networks/*", allowed},

	{libpod, "POST", "/pods/create", onBody(podCreate)},
	{libpod, "GET", "/pods/json", allowed},
	{libpod, "GET", "/pods/stats", allowed},
	{libpod, "POST", "/pods/prune", allowed},
	{libpod, "GET", "/pods/*/json", allowed},
	{libpod, "GET", "/pods/*/exists", allowed},
	{libpod, "GET", "/pods/*/top", allowed},
	{libpod, "POST", "/pods/*/start", allowed},
	{libpod, "POST", "/pods/*/stop", allowed},
	{libpod, "POST", "/pods/*/restart", allowed},
	{libpod, "POST", "/pods/*/kill", allowed},
	{libpod, "POST", "/pods/*/pause", allowed},
	{libpod, "POST", "/pods/*/unpause", allowed},
	{libpod, "DELETE", "/pods/*", allowed},
	{libpod, "GET", "/generate/kube", allowed},
	{libpod, "GET", "/kube/generate", allowed},
	{libpod, "*", "/play/kube", refused("kube YAML can mount host paths")},
	{libpod, "*", "/kube/play", refused("kube YAML can mount host paths")},
	{libpod, "*", "/kube/apply", refused("it deploys to a Kubernetes cluster")},
	{libpod, "*", "/quadlets", refused("quadlets install systemd units")},
	{libpod, "*", "/quadlets/**", refused("quadlets install systemd units")},

	{docker, "GET", "/secrets", allowed},
	{libpod, "GET", "/secrets/json", allowed},
	{docker, "POST", "/secrets/create", onBody(dockerSecret)},
	{libpod, "POST", "/secrets/create", onQuery(libpodSecret)},
	{docker, "GET", "/secrets/*", allowed},
	{libpod, "GET", "/secrets/*/json", allowed},
	{libpod, "GET", "/secrets/*/exists", allowed},
	{both, "DELETE", "/secrets/*", allowed},

	{docker, "*", "/plugins", refused("plugins run with host privileges")},
	{docker, "*", "/plugins/**", refused("plugins run with host privileges")},
	{docker, "*", "/swarm", refused("swarm mode is not supported")},
	{docker, "*", "/swarm/**", refused("swarm mode is not supported")},
	{docker, "*", "/services", refused("swarm mode is not supported")},
	{docker, "*", "/services/**", refused("swarm mode is not supported")},
	{docker, "*", "/nodes", refused("swarm mode is not supported")},
	{docker, "*", "/nodes/**", refused("swarm mode is not supported")},
})

func expand(rs []route) []route {
	var out []route
	for _, r := range rs {
		if r.api&docker != 0 {
			out = append(out, r)
		}
		if r.api&libpod != 0 {
			l := r
			l.pattern = "/libpod" + r.pattern
			out = append(out, l)
		}
	}
	return out
}

func lookup(method, apiPath string) (route, bool) {
	segs := strings.Split(strings.TrimPrefix(apiPath, "/"), "/")
	for _, r := range routes {
		if !methodMatches(r.methods, method) {
			continue
		}
		if matchSegments(strings.Split(strings.TrimPrefix(r.pattern, "/"), "/"), segs) {
			return r, true
		}
	}
	return route{}, false
}

func methodMatches(methods, method string) bool {
	for _, m := range strings.Fields(methods) {
		if m == "*" || m == method {
			return true
		}
	}
	return false
}

func matchSegments(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if len(segs) == 0 {
		return false
	}
	switch pattern[0] {
	case "**":
		for i := 1; i <= len(segs); i++ {
			if matchSegments(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	case "*":
		return segs[0] != "" && matchSegments(pattern[1:], segs[1:])
	default:
		return pattern[0] == segs[0] && matchSegments(pattern[1:], segs[1:])
	}
}

var versionSegment = regexp.MustCompile(`^v[0-9][0-9A-Za-z.-]*$`)

// apiPath strips the optional version prefix, as in /v1.41/containers/json
// or /v5.0.0/libpod/info. Paths that are not clean are refused: podman's
// router would clean them and match a different route.
func apiPath(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return "", false
	}
	first, rest, _ := strings.Cut(p[1:], "/")
	if versionSegment.MatchString(first) {
		return "/" + rest, true
	}
	return p, true
}
