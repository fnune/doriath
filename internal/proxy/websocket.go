package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/profile"
)

// maxFramesBeforeMessage bounds how many control frames, such as pings, may
// come before the first message. The first message that follows is the one
// that carries the login.
const maxFramesBeforeMessage = 8

// maxLoginMessage is the largest first message that the proxy reads to put
// the token in it. A larger one passes through as it came.
const maxLoginMessage = 64 << 10

func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// forwardWebSocket opens the WebSocket to the host, and puts the token in a
// field of the first message that the client sends. The jail holds only a
// placeholder, which the proxy replaces, so the real token reaches the host
// without a request header. Frames pass in both directions as they are.
func (s *Server) forwardWebSocket(w http.ResponseWriter, r *http.Request, target string, c profile.Credential) {
	v, err := s.secrets.Get(r.Context(), c.Secret)
	if err != nil {
		s.record(Event{Kind: "error", Host: target, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
		deny(w, http.StatusBadGateway, fmt.Sprintf("doriath: cannot load the credential for %s: %v", target, unavailable(err)))
		return
	}
	out := r.Clone(context.WithoutCancel(r.Context()))
	out.URL.Scheme, out.URL.Host, out.Host, out.RequestURI = "https", target, target, ""
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Authorization"} {
		out.Header.Del(h)
	}
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		s.record(Event{Kind: "error", Host: target, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
		deny(w, http.StatusBadGateway, fmt.Sprintf("doriath: upstream %s failed: %v", target, err))
		return
	}
	exe := IdentityFrom(r.Context()).Exe
	s.record(Event{Kind: "request", Host: target, Method: r.Method, Path: r.URL.Path, Exe: exe, Status: resp.StatusCode})
	backend, ok := resp.Body.(io.ReadWriteCloser)
	if resp.StatusCode != http.StatusSwitchingProtocols || !ok {
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	defer backend.Close()
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.record(Event{Kind: "error", Host: target, Path: r.URL.Path, Reason: "cannot hijack the WebSocket: " + err.Error()})
		return
	}
	defer conn.Close()
	resp.Body = nil
	if err := resp.Write(brw); err != nil || brw.Flush() != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_ = putTokenInFirstMessage(backend, brw.Reader, c.Field, string(v.Reveal()))
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, backend)
		done <- struct{}{}
	}()
	// A WebSocket ends its TCP connection only after its close handshake, so
	// the end of one direction ends both.
	<-done
}

type wsFrame struct {
	raw     []byte
	fin     bool
	opcode  byte
	masked  bool
	payload []byte
}

// readFrame reads one frame of RFC 6455 from a client. It returns the raw
// bytes too, so a frame that the proxy leaves alone passes unchanged. A
// payload over limit is not read: raw holds the header, and payload is nil.
func readFrame(r *bufio.Reader, limit int) (wsFrame, error) {
	var f wsFrame
	head := make([]byte, 2, 14)
	if _, err := io.ReadFull(r, head); err != nil {
		return f, err
	}
	f.fin, f.opcode, f.masked = head[0]&0x80 != 0, head[0]&0x0f, head[1]&0x80 != 0
	length := uint64(head[1] & 0x7f)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return f, err
		}
		head = append(head, ext...)
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return f, err
		}
		head = append(head, ext...)
		length = binary.BigEndian.Uint64(ext)
	}
	var key []byte
	if f.masked {
		key = make([]byte, 4)
		if _, err := io.ReadFull(r, key); err != nil {
			return f, err
		}
		head = append(head, key...)
	}
	f.raw = head
	if length > uint64(limit) {
		return f, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return f, err
	}
	f.raw = append(f.raw, payload...)
	if f.masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	f.payload = payload
	return f, nil
}

// maskedTextFrame builds a frame that a client sends: a text message, masked
// with a new random key.
func maskedTextFrame(payload []byte) []byte {
	var head []byte
	switch n := len(payload); {
	case n < 126:
		head = []byte{0x81, 0x80 | byte(n)}
	case n <= 0xffff:
		head = []byte{0x81, 0x80 | 126, 0, 0}
		binary.BigEndian.PutUint16(head[2:], uint16(n))
	default:
		head = make([]byte, 10)
		head[0], head[1] = 0x81, 0x80|127
		binary.BigEndian.PutUint64(head[2:], uint64(n))
	}
	key := make([]byte, 4)
	_, _ = rand.Read(key)
	frame := slices.Concat(head, key)
	for i, b := range payload {
		frame = append(frame, b^key[i%4])
	}
	return frame
}

// putTokenInFirstMessage copies what the client sends to the server. In the
// first message, a text message that holds a JSON object with the field, the
// field gets the token, whatever the client put there. Every other byte
// passes as it came.
func putTokenInFirstMessage(dst io.Writer, src *bufio.Reader, field, token string) error {
	for range maxFramesBeforeMessage {
		f, err := readFrame(src, maxLoginMessage)
		if err != nil {
			return err
		}
		switch {
		case f.opcode >= 0x8:
			if _, err := dst.Write(f.raw); err != nil {
				return err
			}
			continue
		case f.opcode == 0x1 && f.fin && f.masked && f.payload != nil:
			if rewritten, ok := withToken(f.payload, field, token); ok {
				_, err := dst.Write(maskedTextFrame(rewritten))
				if err != nil {
					return err
				}
				_, err = io.Copy(dst, src)
				return err
			}
		}
		if _, err := dst.Write(f.raw); err != nil {
			return err
		}
		break
	}
	_, err := io.Copy(dst, src)
	return err
}

func withToken(message []byte, field, token string) ([]byte, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(message, &obj) != nil {
		return nil, false
	}
	if _, ok := obj[field]; !ok {
		return nil, false
	}
	value, err := json.Marshal(token)
	if err != nil {
		return nil, false
	}
	obj[field] = value
	out, err := json.Marshal(obj)
	return out, err == nil
}
