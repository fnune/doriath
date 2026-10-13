// Package audit writes one JSON line per grant, denial and approval, so the
// person can see afterwards what an agent reached and what it was refused.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/proxy"
)

type Log struct {
	w       io.Writer
	now     func() time.Time
	session string
	profile string
	mu      sync.Mutex
}

func New(w io.Writer, now func() time.Time, session, profile string) *Log {
	return &Log{w: w, now: now, session: session, profile: profile}
}

// OpenFile opens the audit log for appending, creating it with mode 0600.
func OpenFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return f, nil
}

type record struct {
	Time    time.Time `json:"time"`
	Session string    `json:"session"`
	Profile string    `json:"profile"`
	Event   string    `json:"event"`
	Data    any       `json:"data,omitempty"`
}

func (l *Log) Write(event string, data any) {
	line, err := json.Marshal(record{Time: l.now().UTC(), Session: l.session, Profile: l.profile, Event: event, Data: data})
	if err != nil {
		line, _ = json.Marshal(record{Time: l.now().UTC(), Session: l.session, Profile: l.profile, Event: "audit-error", Data: err.Error()})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(line, '\n'))
}

func (l *Log) Egress(e proxy.Event) { l.Write("egress", e) }

func (l *Log) Requested(req approval.Request) { l.Write("approval-requested", req) }

func (l *Log) Decided(req approval.Request, d approval.Decision) {
	l.Write("approval-decided", struct {
		Request  approval.Request  `json:"request"`
		Decision approval.Decision `json:"decision"`
	}{req, d})
}
