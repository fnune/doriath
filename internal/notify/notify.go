// Package notify shows approval requests as desktop notifications with
// action buttons, through the freedesktop notification service.
package notify

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/fnune/girdle/internal/approval"
)

const (
	busName       = "org.freedesktop.Notifications"
	objPath       = "/org/freedesktop/Notifications"
	iface         = "org.freedesktop.Notifications"
	appName       = "Girdle of Melian"
	urgencyHi     = byte(2)
	urgencyNormal = byte(1)
)

const (
	actionAllowOnce    = "allow-once"
	actionAllowSession = "allow-session"
	actionDeny         = "deny"
	actionOpen         = "open"
)

// Actions are the buttons, as key and label pairs in the order the
// specification wants.
func Actions(req approval.Request) []string {
	switch req.Kind {
	case approval.KindRule:
		return []string{actionAllowSession, "Allow for this session", actionDeny, "Ignore"}
	case approval.KindPath:
		return []string{actionAllowSession, "Allow for this session", actionDeny, "Deny"}
	}
	a := []string{actionAllowOnce, "Allow once", actionAllowSession, "Allow for this session", actionDeny, "Deny"}
	if safeURL(req.URL) {
		a = append(a, actionOpen, "Open link")
	}
	return a
}

func safeURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// DecisionFor maps a pressed button to a decision. Opening the link is not a
// decision.
func DecisionFor(action string) (approval.Decision, bool) {
	switch action {
	case actionAllowOnce:
		return approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "desktop"}, true
	case actionAllowSession:
		return approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "desktop"}, true
	case actionDeny:
		return approval.Decision{Verdict: approval.VerdictDeny, By: "desktop"}, true
	}
	return approval.Decision{}, false
}

func Body(req approval.Request, now time.Time) string {
	var b strings.Builder
	if req.Kind == approval.KindTool {
		agent := req.Agent
		if agent == "" {
			agent = "the agent"
		}
		fmt.Fprintf(&b, "<i>Written by %s, not by girdle.</i>\n", html.EscapeString(agent))
	}
	if req.Details != "" {
		fmt.Fprintf(&b, "<tt>%s</tt>\n", html.EscapeString(req.Details))
	}
	if safeURL(req.URL) {
		fmt.Fprintf(&b, "Link: %s\n", html.EscapeString(req.URL))
	}
	if req.Scope != "" {
		fmt.Fprintf(&b, "Allow for this session covers: <tt>%s</tt>\n", html.EscapeString(req.Scope))
	}
	fmt.Fprintf(&b, "Profile %s, session %s.", html.EscapeString(req.Profile), html.EscapeString(req.Session))
	if !req.Expires.IsZero() {
		fmt.Fprintf(&b, " Expires in %s.", req.Expires.Sub(now).Round(time.Second))
	}
	fmt.Fprintf(&b, " Or run: girdle approvals")
	return b.String()
}

type Opener interface {
	Open(url string) error
}

type Desktop struct {
	conn   *dbus.Conn
	opener Opener
	now    func() time.Time

	owner string

	mu       sync.Mutex
	handlers map[uint32]func(action string)
}

func NewDesktop(opener Opener, now func() time.Time) (*Desktop, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect to the session bus: %w", err)
	}
	d := &Desktop{conn: conn, opener: opener, now: now, handlers: map[uint32]func(string){}}
	for _, member := range []string{"ActionInvoked", "NotificationClosed"} {
		if err := conn.AddMatchSignal(dbus.WithMatchSender(busName), dbus.WithMatchObjectPath(objPath), dbus.WithMatchInterface(iface), dbus.WithMatchMember(member)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("subscribe to %s: %w", member, err)
		}
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	go d.dispatch(signals)
	return d, nil
}

func (d *Desktop) Close() error { return d.conn.Close() }

func (d *Desktop) fromServer(sender string) bool {
	if sender != "" && sender == d.owner {
		return true
	}
	var owner string
	if err := d.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, busName).Store(&owner); err != nil {
		return false
	}
	d.owner = owner
	return sender == owner
}

// Capabilities lists what the notification server supports, such as
// "actions" for buttons.
func (d *Desktop) Capabilities() ([]string, error) {
	var caps []string
	if err := d.conn.Object(busName, objPath).Call(iface+".GetCapabilities", 0).Store(&caps); err != nil {
		return nil, fmt.Errorf("ask the notification server what it supports: %w", err)
	}
	return caps, nil
}

func (d *Desktop) dispatch(signals <-chan *dbus.Signal) {
	for s := range signals {
		if len(s.Body) < 2 || !d.fromServer(s.Sender) {
			continue
		}
		id, ok := s.Body[0].(uint32)
		if !ok {
			continue
		}
		d.mu.Lock()
		h := d.handlers[id]
		if s.Name == iface+".NotificationClosed" {
			delete(d.handlers, id)
		}
		d.mu.Unlock()
		if h == nil {
			continue
		}
		if s.Name == iface+".ActionInvoked" {
			if action, ok := s.Body[1].(string); ok {
				h(action)
			}
		}
	}
}

func (d *Desktop) Notify(_ context.Context, req approval.Request, respond func(approval.Decision)) (func(), error) {
	hints := map[string]dbus.Variant{
		"urgency":       dbus.MakeVariant(Urgency(req)),
		"resident":      dbus.MakeVariant(true),
		"desktop-entry": dbus.MakeVariant("girdle"),
	}
	var id uint32
	call := d.conn.Object(busName, objPath).Call(iface+".Notify", 0,
		appName, uint32(0), "dialog-password", req.Summary, Body(req, d.now()), Actions(req), hints, int32(0))
	if err := call.Store(&id); err != nil {
		return nil, fmt.Errorf("show notification: %w", err)
	}
	d.mu.Lock()
	d.handlers[id] = func(action string) {
		if action == actionOpen && safeURL(req.URL) {
			_ = d.opener.Open(req.URL)
			return
		}
		if dec, ok := DecisionFor(action); ok {
			respond(dec)
		}
	}
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		delete(d.handlers, id)
		d.mu.Unlock()
		_ = d.conn.Object(busName, objPath).Call(iface+".CloseNotification", 0, id).Err
	}, nil
}

// Urgency keeps held requests on screen, because an agent is waiting, and
// lets drafted rules wait in the notification history like any other
// notification.
func Urgency(req approval.Request) byte {
	if req.Kind == approval.KindRule {
		return urgencyNormal
	}
	return urgencyHi
}

// Inform shows a message without buttons, for events that need attention
// but no decision.
func (d *Desktop) Inform(title, body string) error {
	title = "Agent: " + title
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgencyNormal), "desktop-entry": dbus.MakeVariant("girdle")}
	return d.conn.Object(busName, objPath).Call(iface+".Notify", 0,
		appName, uint32(0), "dialog-information", title, html.EscapeString(body), []string{}, hints, int32(-1)).Err
}

func (None) Inform(string, string) error { return nil }

// None is used when desktop notifications are off. Requests still wait in
// the queue for girdle approvals.
type None struct{}

func (None) Notify(context.Context, approval.Request, func(approval.Decision)) (func(), error) {
	return func() {}, nil
}
