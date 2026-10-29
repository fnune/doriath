package sni

import (
	"fmt"
	"image"
	"image/color"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/fnune/doriath/internal/dbustest"
	"github.com/fnune/doriath/internal/tray"
)

type fakeWatcher struct {
	mu         sync.Mutex
	registered []string
}

func (w *fakeWatcher) RegisterStatusNotifierItem(service string) *dbus.Error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.registered = append(w.registered, service)
	return nil
}

func (w *fakeWatcher) services() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.registered)
}

func startWatcher(t *testing.T) (*dbus.Conn, *fakeWatcher) {
	t.Helper()
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	w := &fakeWatcher{}
	if err := conn.Export(w, watcherPath, watcherName); err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("own the watcher name: %v, %v", reply, err)
	}
	return conn, w
}

func eventually(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("timed out")
}

func square(c color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	for y := range 2 {
		for x := range 2 {
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

type fixture struct {
	item      *Item
	client    *dbus.Conn
	watcher   *fakeWatcher
	activated chan string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", dbustest.PrivateBus(t))
	watcherConn, watcher := startWatcher(t)
	t.Cleanup(func() { _ = watcherConn.Close() })
	activated := make(chan string, 256)
	idle := []*image.NRGBA{square(color.NRGBA{R: 1, G: 2, B: 3, A: 255})}
	waiting := []*image.NRGBA{square(color.NRGBA{R: 9, G: 8, B: 7, A: 128})}
	item, err := New(idle, waiting, func(token string) { activated <- token })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = item.Close() })
	client, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return fixture{item: item, client: client, watcher: watcher, activated: activated}
}

func (f fixture) prop(t *testing.T, name string) any {
	t.Helper()
	v, err := f.client.Object(f.item.name, itemPath).GetProperty(itemIface + "." + name)
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	return v.Value()
}

func TestItemRegistersAndShowsTheState(t *testing.T) {
	f := newFixture(t)
	eventually(t, func() bool { return slices.Equal(f.watcher.services(), []string{f.item.name}) })

	if got := f.prop(t, "Status"); got != "Active" {
		t.Errorf("status = %v", got)
	}
	var icon []pixmap
	if err := dbus.Store([]any{f.prop(t, "IconPixmap")}, &icon); err != nil {
		t.Fatal(err)
	}
	if len(icon) != 1 || icon[0].W != 2 || !slices.Equal(icon[0].Pix[:4], []byte{255, 1, 2, 3}) {
		t.Errorf("idle icon = %v", icon)
	}

	if err := f.client.AddMatchSignal(dbus.WithMatchInterface(itemIface)); err != nil {
		t.Fatal(err)
	}
	signals := make(chan *dbus.Signal, 8)
	f.client.Signal(signals)
	if err := f.item.Show(tray.State{Waiting: 2}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for range 3 {
		select {
		case s := <-signals:
			names = append(names, s.Name)
		case <-time.After(2 * time.Second):
			t.Fatalf("signals = %v", names)
		}
	}
	if want := []string{itemIface + ".NewIcon", itemIface + ".NewStatus", itemIface + ".NewToolTip"}; !slices.Equal(names, want) {
		t.Errorf("signals = %v, want %v", names, want)
	}
	if got := f.prop(t, "Status"); got != "NeedsAttention" {
		t.Errorf("status = %v", got)
	}
	if err := dbus.Store([]any{f.prop(t, "IconPixmap")}, &icon); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(icon[0].Pix[:4], []byte{128, 9, 8, 7}) {
		t.Errorf("waiting icon = %v", icon)
	}
	var tip tooltip
	if err := dbus.Store([]any{f.prop(t, "ToolTip")}, &tip); err != nil {
		t.Fatal(err)
	}
	if tip.Text != "2 requests waiting" {
		t.Errorf("tooltip = %+v", tip)
	}
}

func TestItemOpensWithTheActivationToken(t *testing.T) {
	f := newFixture(t)
	obj := f.client.Object(f.item.name, itemPath)
	if err := obj.Call(itemIface+".ProvideXdgActivationToken", 0, "token-1").Err; err != nil {
		t.Fatal(err)
	}
	if err := obj.Call(itemIface+".Activate", 0, int32(0), int32(0)).Err; err != nil {
		t.Fatal(err)
	}
	if got := <-f.activated; got != "token-1" {
		t.Errorf("token = %q", got)
	}
	if err := obj.Call(itemIface+".Activate", 0, int32(0), int32(0)).Err; err != nil {
		t.Fatal(err)
	}
	if got := <-f.activated; got != "" {
		t.Errorf("a token works once, got %q again", got)
	}
}

func TestItemUsesTheTokenSentJustBeforeEachClick(t *testing.T) {
	f := newFixture(t)
	obj := f.client.Object(f.item.name, itemPath)
	const clicks = 200
	for i := range clicks {
		obj.Go(itemIface+".ProvideXdgActivationToken", dbus.FlagNoReplyExpected, nil, fmt.Sprint("token-", i))
		obj.Go(itemIface+".Activate", dbus.FlagNoReplyExpected, nil, int32(0), int32(0))
	}
	got := map[string]bool{}
	for range clicks {
		select {
		case token := <-f.activated:
			got[token] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("%d of %d clicks opened the page", len(got), clicks)
		}
	}
	for i := range clicks {
		if want := fmt.Sprint("token-", i); !got[want] {
			t.Errorf("no click used %s; tokens used: %d", want, len(got))
			break
		}
	}
}

func TestItemOpensWithoutAToken(t *testing.T) {
	f := newFixture(t)
	if err := f.client.Object(f.item.name, itemPath).Call(itemIface+".Activate", 0, int32(0), int32(0)).Err; err != nil {
		t.Fatal(err)
	}
	if got := <-f.activated; got != "" {
		t.Errorf("token = %q", got)
	}
}

func TestItemRegistersAgainWhenAStatusAreaStarts(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", dbustest.PrivateBus(t))
	item, err := New(nil, nil, func(string) {})
	if err != nil {
		t.Fatalf("a missing status area is not an error: %v", err)
	}
	t.Cleanup(func() { _ = item.Close() })
	conn, watcher := startWatcher(t)
	t.Cleanup(func() { _ = conn.Close() })
	eventually(t, func() bool { return slices.Equal(watcher.services(), []string{item.name}) })
}
