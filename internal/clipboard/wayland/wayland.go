// Package wayland serves a clipboard to the jail as a Wayland display that
// offers only a seat without input and the data-control protocols, which
// clipboard tools such as wl-paste and arboard speak. The jail gets no
// surfaces, input or screen, and cannot set your clipboard.
package wayland

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/clipboard"
)

// Serve answers each client of l from src until ctx ends. onError, if set,
// learns why a client was dropped or a read failed.
func Serve(ctx context.Context, l net.Listener, src clipboard.Source, onError func(error)) error {
	if onError == nil {
		onError = func(error) {}
	}
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl := newClient(uc, src, onError)
			if err := cl.serve(ctx); err != nil {
				onError(err)
			}
		}()
	}
}

type iface int

const (
	ifaceDisplay iface = iota
	ifaceRegistry
	ifaceCallback
	ifaceSeat
	ifaceManager
	ifaceDevice
	ifaceSource
	ifaceOffer
)

// family tells the two data-control protocols apart. They have the same
// requests and events; only their names and versions differ.
type family int

const (
	familyExt family = iota
	familyWlr
)

type object struct {
	iface   iface
	family  family
	version uint32
}

type global struct {
	name    uint32
	iface   string
	version uint32
	object  object
}

const (
	displayID     = 1
	firstServerID = 0xff000000
	// A Wayland message is at most 4096 bytes, and a client sends at most
	// 28 descriptors with one.
	maxMessage = 4096
	maxFDs     = 28
)

var globals = []global{
	{1, "wl_seat", 5, object{iface: ifaceSeat}},
	{2, "ext_data_control_manager_v1", 1, object{iface: ifaceManager, family: familyExt}},
	{3, "zwlr_data_control_manager_v1", 2, object{iface: ifaceManager, family: familyWlr}},
}

// Opcodes, in the order the protocol files declare them.
const (
	displaySync        = 0
	displayGetRegistry = 1
	displayError       = 0
	displayDeleteID    = 1

	registryBind   = 0
	registryGlobal = 0

	callbackDone = 0

	seatRelease      = 3
	seatCapabilities = 0
	seatName         = 1

	managerCreateSource = 0
	managerGetDevice    = 1
	managerDestroy      = 2

	deviceSetSelection        = 0
	deviceDestroy             = 1
	deviceSetPrimarySelection = 2
	deviceDataOffer           = 0
	deviceSelection           = 1
	devicePrimarySelection    = 3

	sourceOffer     = 0
	sourceDestroy   = 1
	sourceCancelled = 1

	offerReceive = 0
	offerDestroy = 1
	offerOffer   = 0
)

// Error codes of wl_display, and wl_seat's for a missing capability.
const (
	errInvalidObject     = 0
	errInvalidMethod     = 1
	errImplementation    = 3
	errMissingCapability = 0
)

type client struct {
	conn    *net.UnixConn
	src     clipboard.Source
	onError func(error)
	objects map[uint32]object
	fds     []int
	next    uint32
}

func newClient(conn *net.UnixConn, src clipboard.Source, onError func(error)) *client {
	return &client{
		conn:    conn,
		src:     src,
		onError: onError,
		objects: map[uint32]object{displayID: {iface: ifaceDisplay}},
		next:    firstServerID,
	}
}

// protocolError ends the connection after telling the client why.
type protocolError struct {
	object uint32
	code   uint32
	msg    string
}

func (e protocolError) Error() string {
	return fmt.Sprintf("wayland client error on object %d: %s", e.object, e.msg)
}

func (c *client) serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
	defer stop()
	defer c.closeFDs()
	buf := make([]byte, 0, maxMessage)
	data := make([]byte, maxMessage)
	oob := make([]byte, unix.CmsgSpace(maxFDs*4))
	for {
		n, oobn, _, _, err := c.conn.ReadMsgUnix(data[:maxMessage-len(buf)], oob)
		if err := c.takeFDs(oob[:oobn]); err != nil {
			return err
		}
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, unix.ECONNRESET) || n == 0 {
				return nil
			}
			return err
		}
		buf = append(buf, data[:n]...)
		for len(buf) >= 8 {
			size := int(binary.LittleEndian.Uint32(buf[4:]) >> 16)
			if size < 8 || size%4 != 0 || size > maxMessage {
				return c.fail(protocolError{displayID, errInvalidMethod, "malformed message"})
			}
			if len(buf) < size {
				break
			}
			m := message{
				object: binary.LittleEndian.Uint32(buf),
				opcode: uint16(binary.LittleEndian.Uint32(buf[4:])),
				args:   buf[8:size],
			}
			if err := c.handle(ctx, m); err != nil {
				return c.fail(err)
			}
			buf = append(buf[:0], buf[size:]...)
		}
	}
}

func (c *client) takeFDs(oob []byte) error {
	if len(oob) == 0 {
		return nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return err
	}
	for i := range msgs {
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		c.fds = append(c.fds, fds...)
	}
	return nil
}

func (c *client) closeFDs() {
	for _, fd := range c.fds {
		_ = unix.Close(fd)
	}
	c.fds = nil
}

func (c *client) fail(err error) error {
	var pe protocolError
	if errors.As(err, &pe) {
		_ = c.send(displayID, displayError, u32(pe.object), u32(pe.code), str(pe.msg))
	}
	return err
}

func (c *client) handle(ctx context.Context, m message) error {
	obj, ok := c.objects[m.object]
	if !ok {
		return protocolError{displayID, errInvalidObject, fmt.Sprintf("no object %d", m.object)}
	}
	switch obj.iface {
	case ifaceDisplay:
		return c.display(m)
	case ifaceRegistry:
		return c.registry(m)
	case ifaceSeat:
		return c.seat(m)
	case ifaceManager:
		return c.manager(ctx, m, obj)
	case ifaceDevice:
		return c.device(m)
	case ifaceSource:
		return c.source(m)
	case ifaceOffer:
		return c.offer(ctx, m)
	}
	return protocolError{m.object, errInvalidMethod, "this object takes no requests"}
}

func (c *client) display(m message) error {
	id, err := m.reader().uint()
	if err != nil {
		return err
	}
	switch m.opcode {
	case displaySync:
		if err := c.create(id, object{iface: ifaceCallback}); err != nil {
			return err
		}
		if err := c.send(id, callbackDone, u32(0)); err != nil {
			return err
		}
		return c.destroy(id)
	case displayGetRegistry:
		if err := c.create(id, object{iface: ifaceRegistry}); err != nil {
			return err
		}
		for _, g := range globals {
			if err := c.send(id, registryGlobal, u32(g.name), str(g.iface), u32(g.version)); err != nil {
				return err
			}
		}
		return nil
	}
	return badOpcode(m)
}

func (c *client) registry(m message) error {
	if m.opcode != registryBind {
		return badOpcode(m)
	}
	r := m.reader()
	name, err := r.uint()
	if err != nil {
		return err
	}
	ifaceName, err := r.string()
	if err != nil {
		return err
	}
	version, err := r.uint()
	if err != nil {
		return err
	}
	id, err := r.uint()
	if err != nil {
		return err
	}
	for _, g := range globals {
		if g.name != name {
			continue
		}
		if g.iface != ifaceName || version == 0 || version > g.version {
			return protocolError{m.object, errInvalidObject, fmt.Sprintf("cannot bind %s version %d as %s", g.iface, g.version, ifaceName)}
		}
		obj := g.object
		obj.version = version
		if err := c.create(id, obj); err != nil {
			return err
		}
		if obj.iface != ifaceSeat {
			return nil
		}
		if err := c.send(id, seatCapabilities, u32(0)); err != nil {
			return err
		}
		if version >= 2 {
			return c.send(id, seatName, str("doriath"))
		}
		return nil
	}
	return protocolError{m.object, errInvalidObject, fmt.Sprintf("no global %d", name)}
}

func (c *client) seat(m message) error {
	if m.opcode == seatRelease {
		return c.destroy(m.object)
	}
	return protocolError{m.object, errMissingCapability, "the jail has no pointer, keyboard or touch"}
}

func (c *client) manager(ctx context.Context, m message, mgr object) error {
	switch m.opcode {
	case managerCreateSource:
		id, err := m.reader().uint()
		if err != nil {
			return err
		}
		return c.create(id, object{iface: ifaceSource, family: mgr.family, version: mgr.version})
	case managerGetDevice:
		r := m.reader()
		id, err := r.uint()
		if err != nil {
			return err
		}
		seat, err := r.uint()
		if err != nil {
			return err
		}
		if c.objects[seat].iface != ifaceSeat || seat == displayID {
			return protocolError{m.object, errInvalidObject, "get_data_device needs a wl_seat"}
		}
		device := object{iface: ifaceDevice, family: mgr.family, version: mgr.version}
		if err := c.create(id, device); err != nil {
			return err
		}
		return c.offerSelection(ctx, id, device)
	case managerDestroy:
		return c.destroy(m.object)
	}
	return badOpcode(m)
}

// offerSelection tells a new device what the clipboard holds. A device sees
// the clipboard of the moment it is made, which is how wl-paste and arboard
// read: one device for each paste.
func (c *client) offerSelection(ctx context.Context, device uint32, d object) error {
	types, err := c.src.Types(ctx)
	if err != nil {
		c.onError(err)
		types = nil
	}
	selection := uint32(0)
	if len(types) > 0 {
		selection = c.next
		c.next++
		c.objects[selection] = object{iface: ifaceOffer, family: d.family, version: d.version}
		if err := c.send(device, deviceDataOffer, u32(selection)); err != nil {
			return err
		}
		for _, t := range types {
			if err := c.send(selection, offerOffer, str(t)); err != nil {
				return err
			}
		}
	}
	if err := c.send(device, deviceSelection, u32(selection)); err != nil {
		return err
	}
	if d.family == familyExt || d.version >= 2 {
		return c.send(device, devicePrimarySelection, u32(0))
	}
	return nil
}

func (c *client) device(m message) error {
	switch m.opcode {
	case deviceSetSelection, deviceSetPrimarySelection:
		source, err := m.reader().uint()
		if err != nil {
			return err
		}
		if source == 0 {
			return nil
		}
		if c.objects[source].iface != ifaceSource || source == displayID {
			return protocolError{m.object, errInvalidObject, "set_selection needs a data source"}
		}
		return c.send(source, sourceCancelled)
	case deviceDestroy:
		return c.destroy(m.object)
	}
	return badOpcode(m)
}

func (c *client) source(m message) error {
	switch m.opcode {
	case sourceOffer:
		_, err := m.reader().string()
		return err
	case sourceDestroy:
		return c.destroy(m.object)
	}
	return badOpcode(m)
}

func (c *client) offer(ctx context.Context, m message) error {
	switch m.opcode {
	case offerReceive:
		mimeType, err := m.reader().string()
		if err != nil {
			return err
		}
		if len(c.fds) == 0 {
			return protocolError{m.object, errImplementation, "receive came without a descriptor"}
		}
		fd := c.fds[0]
		c.fds = c.fds[1:]
		f := os.NewFile(uintptr(fd), "clipboard")
		go func() {
			defer f.Close()
			if err := c.src.Copy(ctx, mimeType, f); err != nil {
				c.onError(err)
			}
		}()
		return nil
	case offerDestroy:
		delete(c.objects, m.object)
		return nil
	}
	return badOpcode(m)
}

func (c *client) create(id uint32, obj object) error {
	if id == 0 || id >= firstServerID {
		return protocolError{displayID, errInvalidObject, fmt.Sprintf("invalid new id %d", id)}
	}
	if _, ok := c.objects[id]; ok {
		return protocolError{displayID, errInvalidObject, fmt.Sprintf("id %d is in use", id)}
	}
	c.objects[id] = obj
	return nil
}

// destroy forgets an object the client made, and tells the client that its
// id is free again.
func (c *client) destroy(id uint32) error {
	delete(c.objects, id)
	return c.send(displayID, displayDeleteID, u32(id))
}

func badOpcode(m message) error {
	return protocolError{m.object, errInvalidMethod, fmt.Sprintf("unknown request %d", m.opcode)}
}

func (c *client) send(object uint32, opcode uint16, args ...[]byte) error {
	size := 8
	for _, a := range args {
		size += len(a)
	}
	out := make([]byte, 8, size)
	binary.LittleEndian.PutUint32(out, object)
	binary.LittleEndian.PutUint32(out[4:], uint32(size)<<16|uint32(opcode))
	for _, a := range args {
		out = append(out, a...)
	}
	_, err := c.conn.Write(out)
	return err
}

func u32(v uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, v)
}

func str(s string) []byte {
	n := len(s) + 1
	out := binary.LittleEndian.AppendUint32(nil, uint32(n))
	out = append(out, s...)
	return append(out, make([]byte, (n+3)&^3-len(s))...)
}

type message struct {
	object uint32
	opcode uint16
	args   []byte
}

func (m message) reader() *reader { return &reader{object: m.object, data: m.args} }

type reader struct {
	object uint32
	data   []byte
}

func (r *reader) short() error {
	return protocolError{r.object, errInvalidMethod, "message too short"}
}

func (r *reader) uint() (uint32, error) {
	if len(r.data) < 4 {
		return 0, r.short()
	}
	v := binary.LittleEndian.Uint32(r.data)
	r.data = r.data[4:]
	return v, nil
}

func (r *reader) string() (string, error) {
	n, err := r.uint()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	padded := int(n+3) &^ 3
	if int(n) > len(r.data) || padded > len(r.data) || r.data[n-1] != 0 {
		return "", r.short()
	}
	s := string(r.data[:n-1])
	r.data = r.data[padded:]
	return s, nil
}
