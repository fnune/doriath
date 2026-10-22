package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebTokenIsCreatedPrivateAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "web-token")
	first, err := webToken(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 || len(first) != 2*webTokenBytes {
		t.Fatalf("token %q, mode %v, err %v", first, info.Mode(), err)
	}
	again, err := webToken(path)
	if err != nil || again != first {
		t.Fatalf("second read %q, %v", again, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := webToken(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a readable token file: %v", err)
	}
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := webToken(path); err == nil {
		t.Fatal("a short token must be refused")
	}
}

const decidedLine = `{"time":"2026-10-22T11:54:00Z","session":"s1","profile":"my-app","event":"approval-decided","data":{"request":{"id":"a1","session":"s1","profile":"my-app","kind":"http","summary":"Push","scope":"x","created":"2026-10-22T11:53:00Z","expires":"2026-10-22T12:03:00Z"},"decision":{"verdict":"allow","lasting":"session","by":"desktop"}}}`

func TestAuditHistoryReadsOnlyWhatWasAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	since := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	egress := `{"time":"2026-10-22T11:50:00Z","session":"s1","profile":"my-app","event":"egress","data":{}}`
	if err := os.WriteFile(path, []byte(egress+"\n"+decidedLine+"\n"+decidedLine[:40]), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &auditHistory{path: path}
	got, err := h.Answered(context.Background(), since)
	if err != nil || len(got) != 1 || got[0].Request.Summary != "Push" || got[0].Decision.By != "desktop" {
		t.Fatalf("got %+v, %v", got, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(decidedLine[40:] + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got, err := h.Answered(context.Background(), since); err != nil || len(got) != 2 {
		t.Fatalf("after the partial line completed: %d records, %v", len(got), err)
	}
	if got, _ := h.Answered(context.Background(), since.Add(24*time.Hour)); len(got) != 0 {
		t.Fatalf("records older than since: %d", len(got))
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := h.Answered(context.Background(), since); err != nil || len(got) != 0 {
		t.Fatalf("after the log was emptied: %d records, %v", len(got), err)
	}
}

func TestAuditHistoryWithoutALog(t *testing.T) {
	h := &auditHistory{path: filepath.Join(t.TempDir(), "missing.jsonl")}
	if got, err := h.Answered(context.Background(), time.Time{}); err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestWebRefusesAnAddressOthersReach(t *testing.T) {
	p := testPaths(t)
	if err := serveWeb(context.Background(), p, []string{"--listen", "0.0.0.0:7341"}, realClock{}, os.Stdout); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("got %v", err)
	}
}
