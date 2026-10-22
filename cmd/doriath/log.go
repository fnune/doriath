package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/session"
)

type auditRecord struct {
	Time    time.Time       `json:"time"`
	Session string          `json:"session"`
	Profile string          `json:"profile"`
	Event   string          `json:"event"`
	Data    json.RawMessage `json:"data"`
}

type logFilter struct {
	session string
	profile string
	denied  bool
	since   time.Time
}

func (f logFilter) keep(r auditRecord) bool {
	if f.session != "" && r.Session != f.session {
		return false
	}
	if f.profile != "" && r.Profile != f.profile {
		return false
	}
	if !f.since.IsZero() && r.Time.Before(f.since) {
		return false
	}
	if f.denied {
		return r.Event == "egress" && strings.Contains(string(r.Data), `"kind":"denied"`) ||
			r.Event == "approval-decided" && strings.Contains(string(r.Data), `"verdict":"deny"`)
	}
	return true
}

func cmdLog(ctx context.Context, args []string, c clock, out io.Writer) error {
	flags := flag.NewFlagSet("log", flag.ContinueOnError)
	var f logFilter
	flags.StringVar(&f.session, "session", "", "only this session")
	flags.StringVar(&f.profile, "profile", "", "only this profile")
	flags.BoolVar(&f.denied, "denied", false, "only denials")
	since := flags.Duration("since", 0, "only the last DURATION, such as 1h")
	asJSON := flags.Bool("json", false, "print the records as JSON lines")
	follow := flags.Bool("follow", false, "keep printing new records")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *since > 0 {
		f.since = c.Now().Add(-*since)
	}
	p, err := paths()
	if err != nil {
		return err
	}
	file, err := os.Open(p.AuditLog())
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "No audit log yet.")
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	r := bufio.NewReader(file)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			var rec auditRecord
			if json.Unmarshal(line, &rec) == nil && f.keep(rec) {
				if *asJSON {
					_, _ = out.Write(line)
				} else {
					fmt.Fprintln(out, formatRecord(rec))
				}
			}
			continue
		}
		if errors.Is(err, io.EOF) {
			if !*follow {
				return nil
			}
			if len(line) > 0 {
				r = resumeAfterPartialLine(line, file)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-c.After(500 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			return err
		}
	}
}

func formatRecord(r auditRecord) string { return session.Printable(describeRecord(r)) }

func describeRecord(r auditRecord) string {
	head := fmt.Sprintf("%s  %-10s %-8s ", r.Time.Local().Format("Jan 02 15:04:05"), r.Profile, r.Session)
	var d map[string]any
	_ = json.Unmarshal(r.Data, &d)
	str := func(m map[string]any, k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	switch r.Event {
	case "egress":
		what := str(d, "host")
		if m := str(d, "method"); m != "" {
			what = m + " " + what + str(d, "path")
		}
		line := head + str(d, "kind") + " " + what
		if status, ok := d["status"].(float64); ok {
			line += fmt.Sprintf(" -> %d", int(status))
		}
		if exe := str(d, "exe"); exe != "" {
			line += " by " + exe
		}
		if reason := str(d, "reason"); reason != "" {
			line += " (" + reason + ")"
		}
		return line
	case "approval-requested":
		return head + "asked " + str(d, "id") + ": " + str(d, "summary")
	case "approval-decided":
		req, _ := d["request"].(map[string]any)
		dec, _ := d["decision"].(map[string]any)
		line := head + str(dec, "verdict") + " " + str(req, "id") + ": " + str(req, "summary")
		if by := str(dec, "by"); by != "" {
			line += " (by " + by + ")"
		}
		return line
	case "session-start":
		cmd, _ := d["command"].([]any)
		words := make([]string, 0, len(cmd))
		for _, c := range cmd {
			if s, ok := c.(string); ok {
				if r := []rune(s); len(r) > 40 {
					s = string(r[:40]) + "…"
				}
				words = append(words, s)
			}
		}
		return head + "started in " + str(d, "cwd") + ": " + strings.Join(words, " ")
	case "session-end":
		return head + fmt.Sprintf("ended with exit code %v", d["exit"])
	}
	return head + r.Event + " " + string(r.Data)
}

func resumeAfterPartialLine(partial []byte, rest io.Reader) *bufio.Reader {
	return bufio.NewReader(io.MultiReader(strings.NewReader(string(partial)), rest))
}
