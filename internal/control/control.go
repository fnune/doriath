// Package control is the request protocol on girdle's unix sockets: one JSON
// request per connection, one JSON response back.
package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const maxMessage = 1 << 20

type request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler answers one method. It may block, for example while a request
// waits for a decision.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

type Server struct {
	handlers map[string]Handler
}

func NewServer(handlers map[string]Handler) *Server {
	return &Server{handlers: handlers}
}

func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, maxMessage)).ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) >= maxMessage {
			write(conn, response{Error: "message too large"})
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	go func() {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		cancel()
	}()

	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		write(conn, response{Error: "invalid request: " + err.Error()})
		return
	}
	h, ok := s.handlers[req.Method]
	if !ok {
		write(conn, response{Error: fmt.Sprintf("unknown method %q", req.Method)})
		return
	}
	result, err := h(ctx, req.Params)
	if err != nil {
		write(conn, response{Error: err.Error()})
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		write(conn, response{Error: "encode result: " + err.Error()})
		return
	}
	write(conn, response{Result: data})
}

func write(conn net.Conn, r response) {
	data, _ := json.Marshal(r)
	_, _ = conn.Write(append(data, '\n'))
}

// Call sends one request to the socket and decodes the result into out.
func Call(ctx context.Context, socket, method string, params, out any) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", socket, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	raw, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode params: %w", err)
	}
	data, err := json.Marshal(request{Method: method, Params: raw})
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("send %s: %w", method, err)
	}
	line, err := bufio.NewReaderSize(conn, 64<<10).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("read %s response: %w", method, err)
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("decode %s response: %w", method, err)
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, out)
}

// Decode reads params strictly into a typed value.
func Decode[T any](params json.RawMessage) (T, error) {
	var v T
	if len(params) == 0 {
		return v, errors.New("missing params")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("invalid params: %w", err)
	}
	return v, nil
}
