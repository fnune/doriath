package wayland

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/clipboard"
)

type fakeClipboard struct {
	content map[string][]byte
}

func (f fakeClipboard) Types(context.Context) ([]string, error) {
	var out []string
	for t := range f.content {
		out = append(out, t)
	}
	return out, nil
}

func (f fakeClipboard) Copy(_ context.Context, mimeType string, w io.Writer) error {
	_, err := w.Write(f.content[mimeType])
	return err
}

type asks struct {
	mu     sync.Mutex
	types  []string
	refuse bool
}

func (a *asks) ask(_ context.Context, mimeType string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.types = append(a.types, mimeType)
	if a.refuse {
		return errors.New("refused")
	}
	return nil
}

func (a *asks) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.types...)
}

// serve starts a display for src and returns the environment that points
// wl-paste and wl-copy at it.
func serve(t *testing.T, src clipboard.Source) []string {
	t.Helper()
	for _, tool := range []string{"wl-paste", "wl-copy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	socket := listen(t, src)
	return []string{"WAYLAND_DISPLAY=" + socket, "XDG_RUNTIME_DIR=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
}

func listen(t *testing.T, src clipboard.Source) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "wayland.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, l, src, func(err error) { t.Log(err) })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return socket
}

func run(t *testing.T, env []string, stdin string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatalf("%s %v did not finish: %s", name, args, stderr.String())
	}
	if err != nil {
		return string(out), errors.New(strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

var png = []byte("\x89PNG\r\n\x1a\nnot really")

func copied() fakeClipboard {
	return fakeClipboard{content: map[string][]byte{
		"image/png":  png,
		"text/plain": []byte("hunter2"),
	}}
}

func TestWlPasteListsOnlyTheImageTypes(t *testing.T) {
	a := &asks{}
	env := serve(t, clipboard.Images(copied(), a.ask))
	out, err := run(t, env, "", "wl-paste", "--list-types")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "image/png" {
		t.Errorf("types = %q", out)
	}
	if len(a.seen()) != 0 {
		t.Errorf("listing the types asked you: %v", a.seen())
	}
}

func TestWlPasteReadsTheImageOnceYouAllowIt(t *testing.T) {
	a := &asks{}
	env := serve(t, clipboard.Images(copied(), a.ask))
	out, err := run(t, env, "", "wl-paste", "--type", "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(png) {
		t.Errorf("read %q", out)
	}
	if seen := a.seen(); len(seen) != 1 || seen[0] != "image/png" {
		t.Errorf("asked for %v", seen)
	}
}

func TestWlPasteGetsNothingYouRefuse(t *testing.T) {
	a := &asks{refuse: true}
	env := serve(t, clipboard.Images(copied(), a.ask))
	if out, _ := run(t, env, "", "wl-paste", "--type", "image/png"); out != "" {
		t.Errorf("read %q after a refusal", out)
	}
}

func TestWlPasteNeverGetsText(t *testing.T) {
	a := &asks{}
	env := serve(t, clipboard.Images(copied(), a.ask))
	for _, args := range [][]string{nil, {"--type", "text/plain"}, {"--type", "text"}, {"--primary"}} {
		if out, _ := run(t, env, "", "wl-paste", args...); strings.Contains(out, "hunter2") {
			t.Errorf("wl-paste %v read the text", args)
		}
	}
	for _, asked := range a.seen() {
		if !strings.HasPrefix(asked, "image/") {
			t.Errorf("a text read asked you for %s", asked)
		}
	}
}

func TestWlPasteSeesAnEmptyClipboard(t *testing.T) {
	env := serve(t, clipboard.Images(fakeClipboard{content: map[string][]byte{"text/plain": []byte("x")}}, (&asks{}).ask))
	if out, err := run(t, env, "", "wl-paste", "--list-types"); err == nil || out != "" {
		t.Errorf("a clipboard without images listed %q, %v", out, err)
	}
}

func TestWlCopyCannotSetYourClipboard(t *testing.T) {
	src := copied()
	env := serve(t, clipboard.Images(src, (&asks{}).ask))
	_, _ = run(t, env, "rm -rf ~", "wl-copy", "--foreground", "--type", "image/png")
	out, err := run(t, env, "", "wl-paste", "--type", "image/png")
	if err != nil || out != string(png) {
		t.Errorf("after wl-copy the clipboard reads %q, %v", out, err)
	}
}

type rawClient struct {
	t    *testing.T
	conn *net.UnixConn
	next uint32
}

func dial(t *testing.T, socket string) *rawClient {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawClient{t: t, conn: c, next: 100}
}

func (r *rawClient) send(object uint32, opcode uint16, fds []int, args ...[]byte) {
	r.t.Helper()
	msg := make([]byte, 8)
	for _, a := range args {
		msg = append(msg, a...)
	}
	binary.LittleEndian.PutUint32(msg, object)
	binary.LittleEndian.PutUint32(msg[4:], uint32(len(msg))<<16|uint32(opcode))
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if _, _, err := r.conn.WriteMsgUnix(msg, oob, nil); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawClient) bindDevices(n int) {
	r.send(displayID, displayGetRegistry, nil, u32(2))
	r.send(2, registryBind, nil, u32(1), str("wl_seat"), u32(1), u32(3))
	r.send(2, registryBind, nil, u32(2), str("ext_data_control_manager_v1"), u32(1), u32(4))
	for i := range n {
		r.send(4, managerGetDevice, nil, u32(uint32(5+i)), u32(3))
	}
}

func (r *rawClient) sync() uint32 {
	r.next++
	r.send(displayID, displaySync, nil, u32(r.next))
	return r.next
}

func (r *rawClient) waitDone(callback uint32, timeout time.Duration) error {
	_ = r.conn.SetReadDeadline(time.Now().Add(timeout))
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r.conn, header); err != nil {
			return err
		}
		body := make([]byte, int(binary.LittleEndian.Uint32(header[4:])>>16)-8)
		if _, err := io.ReadFull(r.conn, body); err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(header) == callback && uint16(binary.LittleEndian.Uint32(header[4:])) == callbackDone {
			return nil
		}
	}
}

func (r *rawClient) roundtrip() {
	r.t.Helper()
	if err := r.waitDone(r.sync(), 5*time.Second); err != nil {
		r.t.Fatal(err)
	}
}

type countingClipboard struct {
	mu      sync.Mutex
	lists   int
	active  int
	most    int
	release chan struct{}
}

func (c *countingClipboard) Types(context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists++
	return []string{"image/png"}, nil
}

func (c *countingClipboard) Copy(context.Context, string, io.Writer) error {
	c.mu.Lock()
	c.active++
	c.most = max(c.most, c.active)
	c.mu.Unlock()
	<-c.release
	c.mu.Lock()
	c.active--
	c.mu.Unlock()
	return nil
}

func (c *countingClipboard) counts() (lists, active, most int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lists, c.active, c.most
}

func TestDevicesInALoopListTheTypesOnce(t *testing.T) {
	src := &countingClipboard{}
	r := dial(t, listen(t, src))
	r.bindDevices(10)
	r.roundtrip()
	if lists, _, _ := src.counts(); lists != 1 {
		t.Errorf("ten devices listed the types %d times", lists)
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	return len(entries)
}

func TestDescriptorsBeyondTheCapAreClosed(t *testing.T) {
	r := dial(t, listen(t, &countingClipboard{}))
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) })
	r.roundtrip()
	before := openFDs(t)
	fds := make([]int, maxFDs)
	for i := range fds {
		fds[i] = pipe[1]
	}
	for range 10 {
		r.next++
		r.send(displayID, displaySync, fds, u32(r.next))
	}
	r.roundtrip()
	if after := openFDs(t); after > before+maxPendingFDs {
		t.Errorf("%d descriptors held after %d were sent, want at most %d", after-before, 10*maxFDs, maxPendingFDs)
	}
}

func TestCopiesRunAtMostEightAtATime(t *testing.T) {
	src := &countingClipboard{release: make(chan struct{})}
	r := dial(t, listen(t, src))
	r.bindDevices(1)
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) })
	for range maxCopies + 4 {
		r.send(firstServerID, offerReceive, []int{pipe[1]}, str("image/png"))
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, active, _ := src.counts(); active >= maxCopies || time.Now().After(deadline) {
			break
		}
	}
	time.Sleep(50 * time.Millisecond)
	_, _, most := src.counts()
	close(src.release)
	r.roundtrip()
	if most != maxCopies {
		t.Errorf("%d copies ran at once, want %d", most, maxCopies)
	}
}

func TestAClientBeyondTheCapWaitsForAFreeSlot(t *testing.T) {
	socket := listen(t, &countingClipboard{})
	first := dial(t, socket)
	first.roundtrip()
	for range maxClients - 1 {
		dial(t, socket).roundtrip()
	}
	late := dial(t, socket)
	callback := late.sync()
	if err := late.waitDone(callback, 100*time.Millisecond); err == nil {
		t.Fatal("a client beyond the cap was served")
	}
	_ = first.conn.Close()
	if err := late.waitDone(callback, 5*time.Second); err != nil {
		t.Fatalf("a client got no slot after another left: %v", err)
	}
}
