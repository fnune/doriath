// Package containers brokers the podman API for the jail. It forwards a list
// of endpoints to the session's podman service and checks the requests that
// could reach outside a container: creates, pulls, builds and volumes. It
// pins the digest each tag resolved to on its first pull.
package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/girdle/internal/approval"
)

// Policy is what the profile lets containers use.
type Policy struct {
	// Images are path.Match patterns over fully qualified references, such
	// as "docker.io/library/*", or AnyImage. Empty allows no image.
	Images []string
	// Mounts are the host paths containers may bind: the profile's mounts
	// and caches.
	Mounts []Mount
}

type Mount struct {
	Path     string
	ReadOnly bool
	// Hidden paths are empty in the jail, so no container may bind them or
	// anything that contains them.
	Hidden bool
}

type Approver interface {
	Submit(ctx context.Context, req approval.Request, ttl time.Duration) (approval.Decision, error)
}

// Pins remembers the digest each tag, such as docker.io/library/postgres:16,
// resolved to the first time a profile pulled it.
type Pins interface {
	Pinned(ref string) (digest string, ok bool, err error)
	Pin(ref, digest string) error
}

type Event struct {
	Kind   string `json:"kind"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason,omitempty"`
	Image  string `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`
}

type Recorder interface {
	ContainerAPI(e Event)
}

type Config struct {
	Session string
	Profile string
	// ApprovalTTL bounds how long a push waits for a decision.
	ApprovalTTL time.Duration
	// Resolver resolves symbolic links in bind sources. Nil compares paths
	// as written.
	Resolver Resolver
	// Pins holds the profile's image digests. Nil pins nothing.
	Pins Pins
}

// KindContainers marks approval requests from the broker.
const KindContainers approval.Kind = "containers"

const maxInspectedBody = 2 << 20

type Broker struct {
	cfg       Config
	mu        sync.RWMutex
	checker   checker
	upstream  string
	approver  Approver
	recorder  Recorder
	transport http.RoundTripper
	proxy     *httputil.ReverseProxy
}

// AllowWrite lets later containers bind path writable, after the session
// made it writable in the jail, except for readOnly inside it. Running
// containers keep their mounts.
func (b *Broker) AllowWrite(path string, readOnly []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	mounts := append(slices.Clone(b.checker.policy.Mounts), Mount{Path: path})
	for _, p := range readOnly {
		mounts = append(mounts, Mount{Path: p, ReadOnly: true})
	}
	b.checker.policy.Mounts = mounts
}

func New(policy Policy, upstream string, approver Approver, recorder Recorder, cfg Config) *Broker {
	b := &Broker{
		cfg:      cfg,
		checker:  checker{policy: policy, resolver: cfg.Resolver, profile: cfg.Profile},
		upstream: upstream,
		approver: approver,
		recorder: recorder,
	}
	b.transport = &http.Transport{
		DialContext:        b.dial,
		DisableCompression: true,
		MaxIdleConns:       8,
		IdleConnTimeout:    90 * time.Second,
	}
	b.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "podman"
			pr.Out.Host = "podman"
		},
		Transport:     b.transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			b.record(Event{Kind: "error", Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: the podman service failed: %v", err))
		},
	}
	return b
}

func (b *Broker) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", b.upstream)
}

// Serve accepts clients until the listener closes.
func (b *Broker) Serve(l net.Listener) error {
	srv := &http.Server{Handler: b, ReadHeaderTimeout: 30 * time.Second}
	err := srv.Serve(l)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := apiPath(r.URL.Path)
	if !ok {
		b.refuse(w, r, http.StatusBadRequest, "the request path is not clean")
		return
	}
	rt, _ := lookup(r.Method, p)
	req := request{Method: r.Method, Path: p, Query: r.URL.Query()}
	if rt.treat.body && rt.treat.refused == "" {
		body, tooLarge, err := readBody(r, maxInspectedBody)
		switch {
		case err != nil:
			b.refuse(w, r, http.StatusBadRequest, "cannot read the request body")
			return
		case tooLarge:
			b.refuse(w, r, http.StatusRequestEntityTooLarge, "request bodies over 2 MB cannot be checked")
			return
		}
		req.Body = body
	}

	b.mu.RLock()
	c := b.checker
	b.mu.RUnlock()
	v := c.decide(req)
	if v.refusal != "" {
		b.refuse(w, r, http.StatusForbidden, v.refusal)
		return
	}
	if v.ask != nil {
		if ok, message := b.approved(r, *v.ask); !ok {
			b.refuse(w, r, http.StatusForbidden, message)
			return
		}
	}
	if v.image != nil && !b.runPinned(w, r, req.Body, *v.image) {
		return
	}
	if rt.treat.check != nil {
		b.record(Event{Kind: "allowed", Method: r.Method, Path: r.URL.Path})
	}
	switch {
	case rt.treat.stream:
		b.stream(w, r)
	case v.pull != nil && b.cfg.Pins != nil:
		b.pull(w, r, *v.pull, strings.HasPrefix(p, "/libpod/"))
	default:
		b.proxy.ServeHTTP(w, r)
	}
}

func (b *Broker) approved(r *http.Request, a ask) (bool, string) {
	details := a.details
	if details == "" {
		details = r.Method + " " + r.URL.RequestURI()
	}
	d, err := b.approver.Submit(r.Context(), approval.Request{
		Session: b.cfg.Session,
		Profile: b.cfg.Profile,
		Kind:    KindContainers,
		Summary: a.summary,
		Details: details,
		Scope:   a.scope,
	}, b.cfg.ApprovalTTL)
	if err == nil && d.Verdict == approval.VerdictAllow {
		b.record(Event{Kind: "approved", Method: r.Method, Path: r.URL.Path, Reason: a.summary})
		return true, ""
	}
	reason := "denied"
	if err == nil && d.Verdict == approval.VerdictNone {
		reason = "not approved in time"
	}
	message := fmt.Sprintf("%s was %s", a.summary, reason)
	if err == nil && d.Verdict == approval.VerdictDeny && d.Reason != "" {
		message += ": " + d.Reason
	}
	return false, message
}

func (b *Broker) refuse(w http.ResponseWriter, r *http.Request, status int, reason string) {
	b.record(Event{Kind: "denied", Method: r.Method, Path: r.URL.Path, Reason: reason})
	deny(w, status, "girdle: "+reason)
}

func (b *Broker) record(e Event) {
	if b.recorder != nil {
		b.recorder.ContainerAPI(e)
	}
}

func deny(w http.ResponseWriter, status int, message string) {
	body, _ := json.Marshal(map[string]any{"message": message, "cause": "refused by girdle", "response": status})
	body = append(body, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Girdle-Denied", "1")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func readBody(r *http.Request, limit int64) ([]byte, bool, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, true, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	return data, false, nil
}
