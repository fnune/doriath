package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type echoParams struct {
	Text string `json:"text"`
}

func serve(t *testing.T, handlers map[string]Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "c.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = NewServer(handlers).Serve(context.Background(), l) }()
	return sock
}

func TestCall(t *testing.T) {
	cancelled := make(chan struct{})
	sock := serve(t, map[string]Handler{
		"echo": func(_ context.Context, p json.RawMessage) (any, error) {
			v, err := Decode[echoParams](p)
			if err != nil {
				return nil, err
			}
			return map[string]string{"text": strings.ToUpper(v.Text)}, nil
		},
		"fail": func(context.Context, json.RawMessage) (any, error) { return nil, errors.New("nope") },
		"block": func(ctx context.Context, _ json.RawMessage) (any, error) {
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		},
	})
	var out struct{ Text string }
	if err := Call(context.Background(), sock, "echo", echoParams{Text: "hi"}, &out); err != nil || out.Text != "HI" {
		t.Fatalf("echo = %+v, %v", out, err)
	}
	if err := Call(context.Background(), sock, "echo", map[string]any{"text": "x", "extra": 1}, &out); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: %v", err)
	}
	if err := Call(context.Background(), sock, "fail", struct{}{}, nil); err == nil || err.Error() != "nope" {
		t.Fatalf("fail = %v", err)
	}
	if err := Call(context.Background(), sock, "missing", struct{}{}, nil); err == nil || !strings.Contains(err.Error(), "unknown method") {
		t.Fatalf("missing = %v", err)
	}

	big := strings.Repeat("a", 100_000)
	if err := Call(context.Background(), sock, "echo", echoParams{Text: big}, &out); err != nil || len(out.Text) != len(big) {
		t.Fatalf("large message: %d, %v", len(out.Text), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := Call(ctx, sock, "block", struct{}{}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("block = %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the client must cancel the handler")
	}
}

func TestServerAnswersMalformedRequests(t *testing.T) {
	sock := serve(t, map[string]Handler{
		"unencodable": func(context.Context, json.RawMessage) (any, error) { return func() {}, nil },
	})
	send := func(message string) string {
		t.Helper()
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		go func() { _, _ = io.WriteString(conn, message) }()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("no answer to %.40q: %v", message, err)
		}
		var resp struct{ Error string }
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Error
	}
	for name, tc := range map[string]struct{ message, want string }{
		"too large":      {strings.Repeat("a", maxMessage+1), "message too large"},
		"not JSON":       {"hello\n", "invalid request: "},
		"no result JSON": {`{"method":"unencodable"}` + "\n", "encode result: "},
	} {
		if got := send(tc.message); !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: error %q, want %q", name, got, tc.want)
		}
	}
}

func TestCallWithoutServerNamesTheSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "gone.sock")
	if err := Call(context.Background(), sock, "status", struct{}{}, nil); err == nil || !strings.HasPrefix(err.Error(), "connect to "+sock+": ") {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeNeedsParams(t *testing.T) {
	if _, err := Decode[echoParams](nil); err == nil || err.Error() != "missing params" {
		t.Fatalf("err = %v", err)
	}
}
