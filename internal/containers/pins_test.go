package containers

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
)

var (
	oldDigest = "sha256:" + strings.Repeat("a", 64)
	newDigest = "sha256:" + strings.Repeat("b", 64)
	storedID  = strings.Repeat("c", 64)
)

const postgres16 = "docker.io/library/postgres:16"

func pinHarness(t *testing.T, pinned string) *harness {
	t.Helper()
	h := newHarness(t)
	h.podman.imageID, h.podman.digest = storedID, newDigest
	if pinned != "" {
		h.pins.pins[postgres16] = pinned
	}
	return h
}

var pulls = []struct{ name, path string }{
	{"docker", "/v1.41/images/create?fromImage=postgres&tag=16"},
	{"libpod", "/v5.0.0/libpod/images/pull?reference=postgres:16"},
}

func lastMessage(t *testing.T, body string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("last line of %q: %v", body, err)
	}
	return m
}

func TestFirstPullPins(t *testing.T) {
	for _, p := range pulls {
		t.Run(p.name, func(t *testing.T) {
			h := pinHarness(t, "")
			status, body := h.do(t, http.MethodPost, p.path, "")
			if status != http.StatusOK {
				t.Fatalf("status %d: %s", status, body)
			}
			if m := lastMessage(t, body); m["error"] != nil {
				t.Fatalf("pull refused: %s", body)
			}
			if got := h.pins.pins[postgres16]; got != newDigest {
				t.Fatalf("pin %q", got)
			}
			if len(h.approver.asked) != 0 {
				t.Fatalf("asked %+v", h.approver.asked)
			}
			if !slices.Contains(h.events.kinds(), "image-pinned") {
				t.Fatalf("events %v", h.events.kinds())
			}
		})
	}
}

func TestPullOfPinnedDigestPasses(t *testing.T) {
	h := pinHarness(t, newDigest)
	status, body := h.do(t, http.MethodPost, pulls[0].path, "")
	if status != http.StatusOK || lastMessage(t, body)["error"] != nil {
		t.Fatalf("status %d: %s", status, body)
	}
	if len(h.approver.asked) != 0 || slices.Contains(h.events.kinds(), "image-pinned") {
		t.Fatalf("asked %d times, events %v", len(h.approver.asked), h.events.kinds())
	}
}

func TestChangedDigestAsks(t *testing.T) {
	for _, p := range pulls {
		for _, v := range []approval.Verdict{approval.VerdictAllow, approval.VerdictDeny} {
			t.Run(p.name+" "+string(v), func(t *testing.T) {
				h := pinHarness(t, oldDigest)
				h.approver.verdict = v
				status, body := h.do(t, http.MethodPost, p.path, "")
				if status != http.StatusOK {
					t.Fatalf("status %d: %s", status, body)
				}
				if len(h.approver.asked) != 1 {
					t.Fatalf("asked %d times", len(h.approver.asked))
				}
				req := h.approver.asked[0]
				want := "docker.io/library/postgres:16 changed from sha256:aaaaaaaaaaaa… to sha256:bbbbbbbbbbbb…"
				if req.Summary != want || req.Kind != KindContainers || !strings.Contains(req.Details, newDigest) || !strings.Contains(req.Scope, newDigest) {
					t.Fatalf("request %+v", req)
				}
				m := lastMessage(t, body)
				if v == approval.VerdictAllow {
					if m["error"] != nil || h.pins.pins[postgres16] != newDigest {
						t.Fatalf("pin %q after approval: %s", h.pins.pins[postgres16], body)
					}
					return
				}
				msg, _ := m["error"].(string)
				if !strings.HasPrefix(msg, "doriath: "+want+" was denied") || h.pins.pins[postgres16] != oldDigest {
					t.Fatalf("pin %q after denial: %s", h.pins.pins[postgres16], body)
				}
				if _, detail := m["errorDetail"]; detail != (p.name == "docker") {
					t.Fatalf("error shape for %s: %s", p.name, body)
				}
			})
		}
	}
}

func TestPullByDigestNeedsNoPin(t *testing.T) {
	h := pinHarness(t, "")
	status, body := h.do(t, http.MethodPost, "/v5.0.0/libpod/images/pull?reference=postgres@"+newDigest, "")
	if status != http.StatusOK || lastMessage(t, body)["error"] != nil {
		t.Fatalf("status %d: %s", status, body)
	}
	if len(h.pins.pins) != 0 || slices.ContainsFunc(h.podman.seen(), func(p string) bool { return strings.HasSuffix(p, "/json") }) {
		t.Fatalf("pins %v, upstream saw %v", h.pins.pins, h.podman.seen())
	}
}

func TestFailedPullPinsNothing(t *testing.T) {
	for _, p := range pulls {
		t.Run(p.name, func(t *testing.T) {
			h := pinHarness(t, "")
			h.podman.pullFails = true
			_, body := h.do(t, http.MethodPost, p.path, "")
			if m := lastMessage(t, body); m["error"] != "manifest unknown" {
				t.Fatalf("stream %s", body)
			}
			if len(h.pins.pins) != 0 {
				t.Fatalf("pins %v", h.pins.pins)
			}
		})
	}
}

func TestUnreadableDigestRefuses(t *testing.T) {
	h := pinHarness(t, "")
	h.podman.digest = ""
	_, body := h.do(t, http.MethodPost, pulls[1].path, "")
	msg, _ := lastMessage(t, body)["error"].(string)
	if !strings.Contains(msg, "cannot be pinned") || len(h.pins.pins) != 0 {
		t.Fatalf("stream %s, pins %v", body, h.pins.pins)
	}
}

func TestCreateRunsPinnedDigest(t *testing.T) {
	tests := []struct {
		name, path, body, key string
		pinned                bool
		want                  string
	}{
		{"docker", "/v1.41/containers/create?name=db", `{"Image":"postgres:16","Env":["A=<b>"],"HostConfig":{"NetworkMode":"host"}}`, "Image", true, "docker.io/library/postgres@" + oldDigest},
		{"libpod", "/v5.0.0/libpod/containers/create", `{"image":"docker.io/library/postgres:16","env":{"A":"b"}}`, "image", true, "docker.io/library/postgres@" + oldDigest},
		{"not pinned", "/v1.41/containers/create", `{"Image":"postgres:15"}`, "Image", true, "postgres:15"},
		{"by digest", "/v1.41/containers/create", `{"Image":"postgres@` + newDigest + `"}`, "Image", true, "postgres@" + newDigest},
		{"no pins yet", "/v1.41/containers/create", `{"Image":"postgres:16"}`, "Image", false, "postgres:16"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pin := ""
			if tt.pinned {
				pin = oldDigest
			}
			h := pinHarness(t, pin)
			if status, body := h.do(t, http.MethodPost, tt.path, tt.body); status != http.StatusCreated {
				t.Fatalf("status %d: %s", status, body)
			}
			if len(h.podman.created) != 1 {
				t.Fatalf("created %v", h.podman.created)
			}
			var got, sent map[string]any
			if err := json.Unmarshal([]byte(h.podman.created[0]), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.body), &sent); err != nil {
				t.Fatal(err)
			}
			if got[tt.key] != tt.want {
				t.Fatalf("image %v, want %s", got[tt.key], tt.want)
			}
			delete(got, tt.key)
			delete(sent, tt.key)
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(sent)
			if string(a) != string(b) {
				t.Fatalf("other fields changed: %s, sent %s", a, b)
			}
		})
	}
}
