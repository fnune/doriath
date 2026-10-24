package fswatch

import (
	"context"
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
