package containers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// stream forwards attach and exec start. Podman answers clients that ask for
// an upgrade with 101, and others with a 200 that has no length and turns the
// connection into a raw stream in both directions. ReverseProxy only relays
// the first, so both are relayed here at the connection level once the
// response shows the switch.
func (b *Broker) stream(w http.ResponseWriter, r *http.Request) {
	up, err := b.dial(r.Context(), "unix", b.upstream)
	if err != nil {
		b.record(Event{Kind: "error", Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
		deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: cannot reach the podman service: %v", err))
		return
	}
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.Host, out.RequestURI = "http", "podman", "podman", ""
	if err := out.Write(up); err != nil {
		_ = up.Close()
		deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: cannot write to the podman service: %v", err))
		return
	}
	upr := bufio.NewReader(up)
	resp, err := http.ReadResponse(upr, out)
	if err != nil {
		_ = up.Close()
		deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: the podman service failed: %v", err))
		return
	}
	if !switched(resp) {
		defer up.Close()
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		_ = up.Close()
		deny(w, http.StatusInternalServerError, "girdle: the connection cannot be hijacked")
		return
	}
	if err := writeHead(conn, resp); err != nil {
		_ = conn.Close()
		_ = up.Close()
		return
	}
	pipe(conn, brw.Reader, up, upr)
}

func switched(resp *http.Response) bool {
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}
	return resp.StatusCode == http.StatusOK && resp.ContentLength < 0 && len(resp.TransferEncoding) == 0
}

func writeHead(w io.Writer, resp *http.Response) error {
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %s\r\n", resp.Status); err != nil {
		return err
	}
	if err := resp.Header.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// pipe copies both ways. Reads go through the buffered readers, which may
// already hold stream bytes. A finished direction is half-closed, so that a
// client closing stdin still gets the rest of the output.
func pipe(client net.Conn, clientR io.Reader, up net.Conn, upR io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(up, clientR)
	go cp(client, upR)
	wg.Wait()
	_ = client.Close()
	_ = up.Close()
}
