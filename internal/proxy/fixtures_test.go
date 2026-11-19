package proxy

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/profile"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

type heldFixture struct {
	Name   string          `json:"name"`
	Method string          `json:"method"`
	URL    string          `json:"url"`
	Body   json.RawMessage `json:"body"`
	Refs   []string        `json:"refs"`
}

const fixtureProfile = `
modules = ["github"]

[secrets.github]
command = ["true"]

[[mcp]]
name = "notion"
url = "https://mcp.example.com/notion"
approve = ["notion-create-*", "notion-update-*"]

[[mcp]]
name = "linear"
url = "https://mcp.example.com/linear"
default = "approve"
`

func fixtureHarness(t *testing.T) *harness {
	t.Helper()
	l := &profile.Loader{Profiles: mapFS{"t.toml": fixtureProfile}, Modules: []fs.FS{modules.FS}, Home: "/home/u"}
	p, err := l.Load("t")
	if err != nil {
		t.Fatal(err)
	}
	return newHarnessFor(t, p)
}

func (f heldFixture) request(t *testing.T) *http.Request {
	t.Helper()
	payload := string(f.Body)
	if len(f.Refs) > 0 {
		payload = ""
		for i, ref := range f.Refs {
			old, next := strings.Repeat("a", 40), strings.Repeat("b", 40)
			if deleted, ok := strings.CutPrefix(ref, "-"); ok {
				ref, next = deleted, zeroID
			}
			caps := ""
			if i == 0 {
				caps = "\x00report-status"
			}
			payload += pktLine(old + " " + next + " " + ref + caps + "\n")
		}
		payload += "0000PACK"
	}
	var body *strings.Reader
	if payload != "" {
		body = strings.NewReader(payload)
	}
	req, err := http.NewRequest(f.Method, f.URL, nil)
	if body != nil {
		req, err = http.NewRequest(f.Method, f.URL, body)
		req.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func describeHeld(f heldFixture, status int, held []approval.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n%s %s\n", f.Name, f.Method, f.URL)
	if len(held) == 0 {
		fmt.Fprintf(&b, "not held: %d\n\n", status)
		return b.String()
	}
	req := held[0]
	fmt.Fprintf(&b, "title: %s\n", req.Title())
	if notify.LinkOf(req) {
		fmt.Fprintf(&b, "button: %s %s\n", req.Link.Label, req.Link.URL)
	}
	fmt.Fprintf(&b, "body:\n%s\n\n", notify.Body(req))
	return b.String()
}

func TestHeldRequestsReadAsTheirNotifications(t *testing.T) {
	raw, err := os.ReadFile("testdata/held-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []heldFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	for _, f := range fixtures {
		h := fixtureHarness(t)
		resp, err := h.client().Do(f.request(t))
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		_ = resp.Body.Close()
		h.approver.mu.Lock()
		got.WriteString(describeHeld(f, resp.StatusCode, h.approver.requests))
		h.approver.mu.Unlock()
	}
	const golden = "testdata/held-requests.golden"
	if *update {
		if err := os.WriteFile(golden, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("notifications differ from %s; run go test ./internal/proxy -run %s -update and read the diff:\n%s", golden, t.Name(), got.String())
	}
}
