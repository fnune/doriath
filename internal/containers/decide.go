package containers

import (
	"fmt"
	"net/url"
	"strings"
)

type request struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

type verdict struct {
	refusal string
	ask     *ask
	pull    *imageRef
	image   *imageRef
}

type ask struct {
	summary string
	details string
	scope   string
}

func refuse(format string, args ...any) verdict {
	return verdict{refusal: fmt.Sprintf(format, args...)}
}

func refuseIf(reason string) verdict { return verdict{refusal: reason} }

func running(ref string) verdict {
	if r, ok := tagged(ref); ok {
		return verdict{image: &r}
	}
	return verdict{}
}

type checker struct {
	policy   Policy
	resolver Resolver
	profile  string
}

func (c checker) decide(r request) verdict {
	rt, ok := lookup(r.Method, r.Path)
	if !ok {
		return refuse("%s %s is not an endpoint that doriath forwards to podman", r.Method, r.Path)
	}
	if rt.treat.refused != "" {
		return refuse("%s %s is not allowed: %s", r.Method, r.Path, rt.treat.refused)
	}
	if rt.treat.check == nil {
		return verdict{}
	}
	return rt.treat.check(c, r)
}

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
