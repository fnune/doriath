package tray

import (
	"context"
	"errors"
	"image/color"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/ui"
)

type counts struct {
	mu     sync.Mutex
	values []int
	err    error
}

func (c *counts) Waiting(context.Context) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	n := c.values[0]
	if len(c.values) > 1 {
		c.values = c.values[1:]
	}
	return n, nil
}

type shownStates struct {
	mu     sync.Mutex
	states []State
	seen   chan struct{}
}

func (s *shownStates) Show(st State) error {
	s.mu.Lock()
	s.states = append(s.states, st)
	s.mu.Unlock()
	s.seen <- struct{}{}
	return nil
}

func TestRunShowsOnlyChanges(t *testing.T) {
	counter := &counts{values: []int{0, 0, 2, 2, 0}}
	icon := &shownStates{seen: make(chan struct{}, 8)}
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- Run(ctx, counter, icon, ticks) }()
	<-icon.seen
	for range 4 {
		ticks <- time.Time{}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := []State{{0}, {2}, {0}}
	if !slices.Equal(icon.states, want) {
		t.Fatalf("shown %v, want %v", icon.states, want)
	}
}

func TestRunKeepsTheLastStateWhenCountingFails(t *testing.T) {
	counter := &counts{err: errors.New("no sessions directory")}
	icon := &shownStates{seen: make(chan struct{}, 8)}
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- Run(ctx, counter, icon, ticks) }()
	ticks <- time.Time{}
	cancel()
	if err := <-done; err != nil || len(icon.states) != 0 {
		t.Fatalf("shown %v, %v", icon.states, err)
	}
}

func TestStateText(t *testing.T) {
	for n, want := range map[int]string{0: "No requests waiting", 1: "1 request waiting", 3: "3 requests waiting"} {
		if got := (State{Waiting: n}).Text(); got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
}

func TestRenderDrawsThePageIcons(t *testing.T) {
	const size = 38
	idle, err := Render(ui.Icon(false), size)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := Render(ui.Icon(true), size)
	if err != nil {
		t.Fatal(err)
	}
	gold := color.NRGBA{R: 0xd4, G: 0xb4, B: 0x5e, A: 255}
	dark := color.NRGBA{R: 0x0e, G: 0x15, B: 0x13, A: 255}
	blue := color.NRGBA{R: 0x5a, G: 0xb4, B: 0xe8, A: 255}
	for name, tc := range map[string]struct {
		x, y          int
		idle, waiting color.NRGBA
	}{
		"corner is clear": {0, size - 1, color.NRGBA{}, color.NRGBA{}},
		"center dot":      {19, 19, dark, dark},
		"disc":            {19, 33, gold, gold},
		"badge":           {30, 8, gold, blue},
	} {
		if got := idle.NRGBAAt(tc.x, tc.y); got != tc.idle {
			t.Errorf("%s: idle %v, want %v", name, got, tc.idle)
		}
		if got := waiting.NRGBAAt(tc.x, tc.y); got != tc.waiting {
			t.Errorf("%s: waiting %v, want %v", name, got, tc.waiting)
		}
	}
}

func TestRenderDashesTheRing(t *testing.T) {
	img, err := Render([]byte(`<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="10" fill="none" stroke="#000000" stroke-width="4" stroke-dasharray="15.70796 15.70796"/></svg>`), 40)
	if err != nil {
		t.Fatal(err)
	}
	if a := img.NRGBAAt(27, 27).A; a != 255 {
		t.Errorf("the first dash runs clockwise from the right: alpha %d at the bottom right", a)
	}
	if a := img.NRGBAAt(12, 27).A; a != 0 {
		t.Errorf("the first gap follows it: alpha %d at the bottom left", a)
	}
}

func TestRenderRefusesWhatItCannotDraw(t *testing.T) {
	for svg, want := range map[string]string{
		`<svg viewBox="0 0 10 10"><path d="M0 0"/></svg>`:                     "only circles",
		`<svg viewBox="0 0 10 20"><circle r="1"/></svg>`:                      "square viewBox",
		`<svg viewBox="0 0 10 10"><circle r="1" fill="red"/></svg>`:           "#rrggbb",
		`<svg viewBox="0 0 10 10"><circle r="1" transform="scale(2)"/></svg>`: "unknown attribute",
	} {
		if _, err := Render([]byte(svg), 16); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", svg, err, want)
		}
	}
}
