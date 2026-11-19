package notify

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/term"
)

const (
	busName       = "org.freedesktop.Notifications"
	objPath       = "/org/freedesktop/Notifications"
	iface         = "org.freedesktop.Notifications"
	appName       = "Doriath"
	urgencyHi     = byte(2)
	urgencyNormal = byte(1)
)

const (
	actionAllowOnce    = "allow-once"
	actionAllowSession = "allow-session"
	actionDeny         = "deny"
	actionDenySession  = "deny-session"
	actionDefault      = "default"
	actionLink         = "open-link"
)

type Page interface {
	Running() bool
	Open(request, activation string) error
}

type Browser interface {
	Open(url, activation string) error
}

func Actions(req approval.Request) []string {
	var out []string
	if LinkOf(req) {
		out = append(out, actionLink, req.Link.Label)
	}
	for _, b := range req.Buttons() {
		out = append(out, actionFor[b.Answer], b.Label)
	}
	return out
}

var actionFor = map[approval.Answer]string{
	approval.AnswerOnce:        actionAllowOnce,
	approval.AnswerSession:     actionAllowSession,
	approval.AnswerDeny:        actionDeny,
	approval.AnswerDenySession: actionDenySession,
}

func LinkOf(req approval.Request) bool {
	return req.Link.Label != "" && safeURL(req.Link.URL)
}

func safeURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func DecisionFor(action string) (approval.Decision, bool) {
	for answer, key := range actionFor {
		if key == action {
			return answer.Decision("desktop")
		}
	}
	return approval.Decision{}, false
}

// Body holds what decides the answer, most specific first. The web page
// shows the rest: the raw request, the scope and the lines to keep it.
func Body(req approval.Request) string {
	var b strings.Builder
	agent := req.Agent
	if agent == "" {
		agent = "the agent"
	}
	if req.Warning != "" {
		fmt.Fprintf(&b, "<b>Warning from doriath:</b> %s\n", markup(term.Printable(req.Warning)))
	}
	if req.Kind == approval.KindTool {
		fmt.Fprintf(&b, "<i>Written by %s, not by doriath.</i>\n", markup(oneLine(agent)))
	}
	for i, f := range req.Facts {
		if i == 0 || f.Label == "" {
			fmt.Fprintf(&b, "%s\n", markup(oneLine(f.Value)))
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", markup(oneLine(f.Label)), markup(oneLine(f.Value)))
	}
	if req.Note != "" {
		fmt.Fprintf(&b, "<i>“%s”</i>\n", markup(oneLine(req.Note)))
	}
	if lead, _ := req.LeadCommand(); lead != "" {
		fmt.Fprintf(&b, "<tt>“%s”</tt>\n", markup(term.PrintableLine(lead)))
	}
	if len(req.Facts) == 0 && req.Details != "" {
		fmt.Fprintf(&b, "<tt>%s</tt>\n", markup(term.PrintableLine(req.Details)))
	}
	if req.SessionDescription != "" {
		fmt.Fprintf(&b, "<i>“%s”</i>", markup(oneLine(req.SessionDescription)))
	} else {
		b.WriteString(markup(oneLine(req.Session)))
	}
	return b.String()
}

func markup(s string) string { return html.EscapeString(s) }

func oneLine(s string) string {
	return strings.Join(strings.Fields(term.Printable(s)), " ")
}

type Desktop struct {
	conn    *dbus.Conn
	Page    Page
	Browser Browser

	owner string

	mu          sync.Mutex
	handlers    map[uint32]func(action, activation string)
	activations map[uint32]string
}

func NewDesktop() (*Desktop, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect to the session bus: %w", err)
	}
	d := &Desktop{conn: conn, handlers: map[uint32]func(string, string){}, activations: map[uint32]string{}}
	for _, member := range []string{"ActivationToken", "ActionInvoked", "NotificationClosed"} {
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
		arg, _ := s.Body[1].(string)
		d.mu.Lock()
		h, activation := d.handlers[id], d.activations[id]
		switch s.Name {
		case iface + ".ActivationToken":
			d.activations[id] = arg
		case iface + ".ActionInvoked":
			delete(d.activations, id)
		case iface + ".NotificationClosed":
			delete(d.handlers, id)
			delete(d.activations, id)
		}
		d.mu.Unlock()
		if h != nil && s.Name == iface+".ActionInvoked" && arg != "" {
			h(arg, activation)
		}
	}
}

func (d *Desktop) Notify(_ context.Context, req approval.Request, respond func(approval.Decision)) (func(), error) {
	hints := map[string]dbus.Variant{
		"urgency":       dbus.MakeVariant(Urgency(req)),
		"resident":      dbus.MakeVariant(true),
		"desktop-entry": dbus.MakeVariant("doriath"),
	}
	actions, body := Actions(req), Body(req)
	page := d.Page != nil && d.Page.Running()
	if page {
		actions = append(actions, actionDefault, "")
	}
	var id uint32
	call := d.conn.Object(busName, objPath).Call(iface+".Notify", 0,
		appName, uint32(0), "dialog-password", oneLineTitle(req.Title()), body, actions, hints, int32(0))
	if err := call.Store(&id); err != nil {
		return nil, fmt.Errorf("show notification: %w", err)
	}
	d.mu.Lock()
	d.handlers[id] = func(action, activation string) {
		if page && action == actionDefault {
			_ = d.Page.Open(req.Session+"/"+req.ID, activation)
			return
		}
		if action == actionLink && d.Browser != nil && LinkOf(req) {
			_ = d.Browser.Open(req.Link.URL, activation)
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
		delete(d.activations, id)
		d.mu.Unlock()
		_ = d.conn.Object(busName, objPath).Call(iface+".CloseNotification", 0, id).Err
	}, nil
}

func Urgency(req approval.Request) byte {
	if req.Kind == approval.KindHost {
		return urgencyNormal
	}
	return urgencyHi
}

func (d *Desktop) Inform(session, title, body string) error {
	title = oneLineTitle("Agent in " + session + ": " + title)
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgencyNormal), "desktop-entry": dbus.MakeVariant("doriath")}
	return d.conn.Object(busName, objPath).Call(iface+".Notify", 0,
		appName, uint32(0), "dialog-information", title, markup(oneLine(body)), []string{}, hints, int32(-1)).Err
}

func (None) Inform(string, string, string) error { return nil }

const maxTitle = 120

func oneLineTitle(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxTitle {
			b.WriteString("…")
			break
		}
		n++
		if term.Unprintable(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

type None struct{}

func (None) Notify(context.Context, approval.Request, func(approval.Decision)) (func(), error) {
	return func() {}, nil
}
