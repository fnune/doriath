package containers

import (
	"fmt"
	"net/url"
	"strings"
)

// request is what the decision needs from an HTTP request. Path has the
// version prefix stripped.
type request struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

// verdict is the outcome of a decision. A zero verdict forwards the request.
type verdict struct {
	// refusal is shown to the client after "girdle: ".
	refusal string
	ask     *ask
}

// ask is a request that needs a person's approval before it is forwarded.
type ask struct {
	summary string
	scope   string
}

func refuse(format string, args ...any) verdict {
	return verdict{refusal: fmt.Sprintf(format, args...)}
}

func refuseIf(reason string) verdict { return verdict{refusal: reason} }

type checker struct {
	policy   Policy
	resolver Resolver
	profile  string
}

// decide applies the route table and the request checks. It does no IO
// beyond the resolver.
func (c checker) decide(r request) verdict {
	rt, ok := lookup(r.Method, r.Path)
	if !ok {
		return refuse("%s %s is not an endpoint that girdle forwards to podman", r.Method, r.Path)
	}
	if rt.treat.refused != "" {
		return refuse("%s %s is not allowed: %s", r.Method, r.Path, rt.treat.refused)
	}
	if rt.treat.check == nil {
		return verdict{}
	}
	return rt.treat.check(c, r)
}

// queryValues reads a parameter the way podman's decoder does, which ignores
// the case of names. Every value counts, so a second spelling cannot hide one.
func queryValues(q url.Values, name string) []string {
	var out []string
	for k, vs := range q {
		if strings.EqualFold(k, name) {
			out = append(out, vs...)
		}
	}
	return out
}

func queryValue(q url.Values, name string) string {
	vs := queryValues(q, name)
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

func first(reasons ...string) string {
	for _, r := range reasons {
		if r != "" {
			return r
		}
	}
	return ""
}
