// Package sni shows the tray icon on Linux desktops through the
// StatusNotifierItem protocol on the session bus. KDE Plasma, waybar,
// Xfce, LXQt and GNOME with the AppIndicator extension show it.
package sni

import (
	"fmt"
	"image"
	"os"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/fnune/doriath/internal/tray"
)

const (
	itemPath    = dbus.ObjectPath("/StatusNotifierItem")
	itemIface   = "org.kde.StatusNotifierItem"
	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = dbus.ObjectPath("/StatusNotifierWatcher")
	propsIface  = "org.freedesktop.DBus.Properties"
	introIface  = "org.freedesktop.DBus.Introspectable"
	noMenu      = dbus.ObjectPath("/NO_DBUSMENU")
)

type pixmap struct {
	W, H int32
	Pix  []byte
}

type tooltip struct {
	IconName string
	Pixmaps  []pixmap
	Title    string
	Text     string
}

type Item struct {
	conn     *dbus.Conn
	name     string
	idle     []pixmap
	waiting  []pixmap
	activate func(token string)

	mu    sync.Mutex
	state tray.State
	token string
}

// New registers the icon with the status area, and again each time a
// status area starts. activate runs on a click, with the activation token
// that lets the compositor raise the window it opens.
func New(idle, waiting []*image.NRGBA, activate func(token string)) (*Item, error) {
	it := &Item{
		name:     fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid()),
		idle:     pixmaps(idle),
		waiting:  pixmaps(waiting),
		activate: activate,
	}
	conn, err := dbus.ConnectSessionBus(dbus.WithIncomingInterceptor(it.handleClicksInArrivalOrder))
	if err != nil {
		return nil, fmt.Errorf("connect to the session bus: %w", err)
	}
	it.conn = conn
	if err := it.start(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return it, nil
}

func (it *Item) start() error {
	for iface, obj := range map[string]any{itemIface: repliesOnly{}, propsIface: properties{it}, introIface: introspection{}} {
		if err := it.conn.Export(obj, itemPath, iface); err != nil {
			return fmt.Errorf("export the tray icon: %w", err)
		}
	}
	reply, err := it.conn.RequestName(it.name, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("own %s: %w", it.name, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("own %s: another process has it", it.name)
	}
	if err := it.conn.AddMatchSignal(
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, watcherName),
	); err != nil {
		return fmt.Errorf("watch for a status area: %w", err)
	}
	signals := make(chan *dbus.Signal, 4)
	it.conn.Signal(signals)
	go it.reregister(signals)
	it.registerWithStatusArea()
	return nil
}

func (it *Item) registerWithStatusArea() {
	_ = it.conn.Object(watcherName, watcherPath).Call(watcherName+".RegisterStatusNotifierItem", 0, it.name).Err
}

func (it *Item) reregister(signals <-chan *dbus.Signal) {
	for s := range signals {
		if s.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(s.Body) < 3 {
			continue
		}
		if owner, _ := s.Body[2].(string); owner != "" {
			it.registerWithStatusArea()
		}
	}
}

func (it *Item) Close() error { return it.conn.Close() }

func (it *Item) Show(s tray.State) error {
	it.mu.Lock()
	before := it.state
	it.state = s
	it.mu.Unlock()
	if (before.Waiting > 0) != (s.Waiting > 0) {
		if err := it.conn.Emit(itemPath, itemIface+".NewIcon"); err != nil {
			return err
		}
		if err := it.conn.Emit(itemPath, itemIface+".NewStatus", status(s)); err != nil {
			return err
		}
	}
	return it.conn.Emit(itemPath, itemIface+".NewToolTip")
}

func status(s tray.State) string {
	if s.Waiting > 0 {
		return "NeedsAttention"
	}
	return "Active"
}

func (it *Item) props() map[string]dbus.Variant {
	it.mu.Lock()
	s := it.state
	it.mu.Unlock()
	icon := it.idle
	if s.Waiting > 0 {
		icon = it.waiting
	}
	return map[string]dbus.Variant{
		"Category":            dbus.MakeVariant("ApplicationStatus"),
		"Id":                  dbus.MakeVariant("doriath"),
		"Title":               dbus.MakeVariant("Doriath"),
		"Status":              dbus.MakeVariant(status(s)),
		"WindowId":            dbus.MakeVariant(int32(0)),
		"IconName":            dbus.MakeVariant(""),
		"IconPixmap":          dbus.MakeVariant(icon),
		"OverlayIconName":     dbus.MakeVariant(""),
		"OverlayIconPixmap":   dbus.MakeVariant([]pixmap{}),
		"AttentionIconName":   dbus.MakeVariant(""),
		"AttentionIconPixmap": dbus.MakeVariant(it.waiting),
		"AttentionMovieName":  dbus.MakeVariant(""),
		"ToolTip":             dbus.MakeVariant(tooltip{Pixmaps: []pixmap{}, Title: "Doriath", Text: s.Text()}),
		"ItemIsMenu":          dbus.MakeVariant(false),
		"Menu":                dbus.MakeVariant(noMenu),
	}
}

func (it *Item) handleClicksInArrivalOrder(msg *dbus.Message) {
	if msg.Type != dbus.TypeMethodCall || header[dbus.ObjectPath](msg, dbus.FieldPath) != itemPath || header[string](msg, dbus.FieldInterface) != itemIface {
		return
	}
	switch header[string](msg, dbus.FieldMember) {
	case "ProvideXdgActivationToken":
		if len(msg.Body) == 1 {
			token, _ := msg.Body[0].(string)
			it.mu.Lock()
			it.token = token
			it.mu.Unlock()
		}
	case "Activate", "ContextMenu":
		it.mu.Lock()
		token := it.token
		it.token = ""
		it.mu.Unlock()
		go it.activate(token)
	}
}

func header[T any](msg *dbus.Message, field dbus.HeaderField) T {
	v, _ := msg.Headers[field].Value().(T)
	return v
}

type repliesOnly struct{}

func (repliesOnly) Activate(int32, int32) *dbus.Error { return nil }

func (repliesOnly) ContextMenu(int32, int32) *dbus.Error { return nil }

func (repliesOnly) SecondaryActivate(int32, int32) *dbus.Error { return nil }

func (repliesOnly) Scroll(int32, string) *dbus.Error { return nil }

func (repliesOnly) ProvideXdgActivationToken(string) *dbus.Error { return nil }

type properties struct{ it *Item }

func (p properties) Get(iface, name string) (dbus.Variant, *dbus.Error) {
	if iface != itemIface {
		return dbus.Variant{}, unknownInterface(iface)
	}
	v, ok := p.it.props()[name]
	if !ok {
		return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.UnknownProperty", []any{name})
	}
	return v, nil
}

func (p properties) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != itemIface {
		return nil, unknownInterface(iface)
	}
	return p.it.props(), nil
}

func (properties) Set(string, string, dbus.Variant) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.PropertyReadOnly", nil)
}

func unknownInterface(iface string) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.UnknownInterface", []any{iface})
}

type introspection struct{}

func (introspection) Introspect() (string, *dbus.Error) { return introspectXML, nil }

func pixmaps(images []*image.NRGBA) []pixmap {
	out := make([]pixmap, 0, len(images))
	for _, img := range images {
		b := img.Bounds()
		pix := make([]byte, 0, 4*b.Dx()*b.Dy())
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				c := img.NRGBAAt(x, y)
				pix = append(pix, c.A, c.R, c.G, c.B)
			}
		}
		out = append(out, pixmap{W: int32(b.Dx()), H: int32(b.Dy()), Pix: pix})
	}
	return out
}

const introspectXML = `<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="i" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
    <method name="Activate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
    <method name="SecondaryActivate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
    <method name="Scroll"><arg name="delta" type="i" direction="in"/><arg name="orientation" type="s" direction="in"/></method>
    <method name="ProvideXdgActivationToken"><arg name="token" type="s" direction="in"/></method>
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewOverlayIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus"><arg name="status" type="s"/></signal>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get"><arg name="interface" type="s" direction="in"/><arg name="property" type="s" direction="in"/><arg name="value" type="v" direction="out"/></method>
    <method name="GetAll"><arg name="interface" type="s" direction="in"/><arg name="properties" type="a{sv}" direction="out"/></method>
    <method name="Set"><arg name="interface" type="s" direction="in"/><arg name="property" type="s" direction="in"/><arg name="value" type="v" direction="in"/></method>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect"><arg name="xml" type="s" direction="out"/></method>
  </interface>
</node>`
