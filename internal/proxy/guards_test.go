package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAbsoluteHTTPSOnOtherPortDenied(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET https://example.com:8443/x HTTP/1.1\r\nHost: example.com:8443\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if h.upstream.count() != 0 {
		t.Fatal("the request reached upstream")
	}
}

func TestInterceptRefusesOtherSNIEvenWithoutVerification(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "github.com", InsecureSkipVerify: true})
	if err := tc.Handshake(); err == nil {
		t.Fatal("the proxy completed a handshake for an SNI other than the CONNECT host")
	}
}

func TestClosingTheConnectionClosesItsListener(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	l := newOneConnListener(server)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept still blocks after the only connection closed")
	}
}

func TestTunnelMismatch(t *testing.T) {
	for _, tc := range []struct {
		host, name string
		tls        bool
		ok         bool
	}{
		{"example.com", "example.com", true, true},
		{"example.com", "EXAMPLE.com.", true, true},
		{"example.com", "github.com", true, false},
		{"example.com", "", true, false},
		{"example.com", "", false, false},
		{"203.0.113.7", "", true, true},
		{"203.0.113.7", "", false, false},
	} {
		if got := tunnelMismatch(tc.host, tc.name, tc.tls) == ""; got != tc.ok {
			t.Errorf("%s %q tls=%v: ok = %v", tc.host, tc.name, tc.tls, got)
		}
	}
}
