// Package containers brokers the podman API for the jail. It forwards a list
// of endpoints to the session's podman service and checks the requests that
// could reach outside a container: creates, pulls, builds and volumes.
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
	"strconv"
	"time"

	"github.com/fnune/girdle/internal/approval"
)

// Policy is what the profile lets containers use.
type Policy struct {
	// Images are path.Match patterns over fully qualified references, such
	// as "docker.io/library/*". Empty allows every image.
	Images []string
	// Mounts are the host paths containers may bind: the profile's mounts
	// and caches.
	Mounts []Mount
}

type Mount struct {
	Path     string
	ReadOnly bool
}

type Approver interface {
	Submit(ctx context.Context, req approval.Request, ttl time.Duration) (approval.Decision, error)
}

type Event struct {
	Kind   string `json:"kind"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason,omitempty"`
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
}

// KindContainers marks approval requests from the broker.
const KindContainers approval.Kind = "containers"

const maxInspectedBody = 2 << 20

type Broker struct {
	cfg      Config
	checker  checker
	upstream string
	approver Approver
	recorder Recorder
	proxy    *httputil.ReverseProxy
}

func New(policy Policy, upstream string, approver Approver, recorder Recorder, cfg Config) *Broker {
	b := &Broker{
		cfg:      cfg,
		checker:  checker{policy: policy, resolver: cfg.Resolver, profile: cfg.Profile},
		upstream: upstream,
		approver: approver,
		recorder: recorder,
	}
	b.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "podman"
			pr.Out.Host = "podman"
		},
		Transport: &http.Transport{
			DialContext:        b.dial,
			DisableCompression: true,
			MaxIdleConns:       8,
			IdleConnTimeout:    90 * time.Second,
		},
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
			// Refused rather than passed through, so that padding cannot
			// hide a field from the check.
			b.refuse(w, r, http.StatusRequestEntityTooLarge, "request bodies over 2 MB cannot be checked")
			return
		}
		req.Body = body
	}

	v := b.checker.decide(req)
	if v.refusal != "" {
		b.refuse(w, r, http.StatusForbidden, v.refusal)
		return
	}
	if v.ask != nil && !b.approved(w, r, *v.ask) {
		return
	}
	if rt.treat.check != nil {
		b.record(Event{Kind: "allowed", Method: r.Method, Path: r.URL.Path})
	}
	if rt.treat.stream {
		b.stream(w, r)
		return
	}
	b.proxy.ServeHTTP(w, r)
}

func (b *Broker) approved(w http.ResponseWriter, r *http.Request, a ask) bool {
	d, err := b.approver.Submit(r.Context(), approval.Request{
		Session: b.cfg.Session,
		Profile: b.cfg.Profile,
		Kind:    KindContainers,
		Summary: a.summary,
		Details: r.Method + " " + r.URL.RequestURI(),
		Scope:   a.scope,
	}, b.cfg.ApprovalTTL)
	if err == nil && d.Verdict == approval.VerdictAllow {
		b.record(Event{Kind: "approved", Method: r.Method, Path: r.URL.Path, Reason: a.summary})
		return true
	}
	reason := "denied"
	if err == nil && d.Verdict == approval.VerdictNone {
		reason = "not approved in time"
	}
	message := fmt.Sprintf("%s was %s", a.summary, reason)
	if err == nil && d.Verdict == approval.VerdictDeny && d.Reason != "" {
		message += ": " + d.Reason
	}
	b.refuse(w, r, http.StatusForbidden, message)
	return false
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

// deny writes the error shape of podman and Docker, whose clients print
// message.
func deny(w http.ResponseWriter, status int, message string) {
	body, _ := json.Marshal(map[string]any{"message": message, "cause": "refused by girdle", "response": status})
	body = append(body, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Girdle-Denied", "1")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// readBody reads up to limit bytes and puts the body back for forwarding.
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
