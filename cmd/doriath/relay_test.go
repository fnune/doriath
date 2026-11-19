package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestABrowserGetsAPageWhenNothingListensInTheJail(t *testing.T) {
	for request, wantPage := range map[string]bool{
		"GET / HTTP/1.1\r\nHost: localhost:47123\r\nAccept: text/html\r\n\r\n": true,
		"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 tls hello":               false,
		"SSH-2.0-OpenSSH_9.9\r\n":                                              false,
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			answerNothingListens(conn, "47123")
		}()
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(client, request); err != nil {
			t.Fatal(err)
		}
		_ = client.(*net.TCPConn).CloseWrite()
		got, _ := io.ReadAll(client)
		_ = client.Close()
		_ = ln.Close()
		page := strings.HasPrefix(string(got), "HTTP/1.1 502 ") && strings.Contains(string(got), "nothing listens on port 47123 in the jail")
		if page != wantPage {
			t.Errorf("%q: got %q", request, got)
		}
	}
}

func TestTheBrowserKeepsThePageWhenItsRequestIsLongerThanWhatDoriathReads(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		answerNothingListens(conn, "47123")
		_ = conn.Close()
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := "GET / HTTP/1.1\r\nHost: localhost:47123\r\nCookie: " + strings.Repeat("a", 64<<10) + "\r\n\r\n"
	go func() { _, _ = io.WriteString(client, request) }()
	time.Sleep(100 * time.Millisecond)
	got, err := io.ReadAll(client)
	if err != nil || !strings.Contains(string(got), "nothing listens on port 47123") {
		t.Errorf("read %d bytes, %v", len(got), err)
	}
}
