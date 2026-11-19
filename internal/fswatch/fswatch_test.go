package fswatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAWatcherReportsANameCreatedInAWatchedFolder(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	if err := w.Add(dir, unix.IN_CREATE); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 4)
	done := make(chan struct{})
	go func() { w.Run(ctx, func(e Event) { events <- e }); close(done) }()
	if err := os.WriteFile(filepath.Join(dir, "lefthook-local.yml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e.Dir != dir || e.Name != "lefthook-local.yml" || e.Mask&unix.IN_CREATE == 0 {
			t.Errorf("event = %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Error("no event")
	}
	cancel()
	<-done
	if err := w.Close(); err != nil {
		t.Error(err)
	}
}

func TestAWatcherReportsAnOverflowOfItsQueue(t *testing.T) {
	limit, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events")
	if err != nil {
		t.Skip(err)
	}
	var max int
	if _, err := fmt.Sscan(string(limit), &max); err != nil || max > 100000 {
		t.Skip("the queue is too long to fill in a test")
	}
	w, err := New()
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = w.Close() }()
	dir := t.TempDir()
	if err := w.Add(dir, unix.IN_CREATE); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= max+10; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprint(i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	overflow := make(chan struct{}, 1)
	go w.Run(ctx, func(e Event) {
		if e.Overflowed() {
			select {
			case overflow <- struct{}{}:
			default:
			}
		}
	})
	select {
	case <-overflow:
	case <-time.After(5 * time.Second):
		t.Error("the watcher dropped the overflow, so a caller cannot know that it missed events")
	}
}
