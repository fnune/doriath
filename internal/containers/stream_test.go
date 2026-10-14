package containers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAllowWriteOpensBindsForLaterContainers(t *testing.T) {
	for name, tc := range map[string]struct{ path, before string }{
		"outside":   {"/data", "outside the mounts and caches"},
		"read-only": {"/ro/x", "read-only in profile"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			create := fmt.Sprintf(`{"Image":"alpine","HostConfig":{"Binds":["%s:/d"]}}`, tc.path)
			status, body := h.do(t, http.MethodPost, "/v1.41/containers/create", create)
			if status != http.StatusForbidden || !strings.Contains(message(t, body), tc.before) {
				t.Fatalf("before: status %d: %s", status, body)
			}
			h.broker.AllowWrite(tc.path)
			if status, body := h.do(t, http.MethodPost, "/v1.41/containers/create", create); status != http.StatusCreated {
				t.Fatalf("after: status %d: %s", status, body)
			}
		})
	}
}

func TestAttachToAMissingContainerRelaysPodmansAnswer(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST /v5.0.0/libpod/containers/gone/attach?stream=true HTTP/1.1\r\nHost: d\r\nContent-Length: 0\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound || message(t, string(b)) != `no container with name or ID "gone" found` {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
}

func TestBrokerWithoutPodmanSaysSo(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "podman.sock")
	ev := &events{}
	b := New(Policy{}, gone, &fakeApprover{}, ev, Config{Profile: "dev", ApprovalTTL: time.Second})
	client := unixClient(serveBroker(t, b))
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodGet, "/v1.41/containers/json", "girdle: the podman service failed: "},
		{http.MethodPost, "/v1.41/containers/abc/attach", "girdle: cannot reach the podman service: "},
	} {
		status, body := do(t, client, tc.method, tc.path, "")
		if status != http.StatusBadGateway || !strings.HasPrefix(message(t, body), tc.want) {
			t.Errorf("%s %s: status %d: %s", tc.method, tc.path, status, body)
		}
	}
	if kinds := ev.kinds(); len(kinds) != 2 || kinds[0] != "error" || kinds[1] != "error" {
		t.Errorf("events %v", kinds)
	}
}
