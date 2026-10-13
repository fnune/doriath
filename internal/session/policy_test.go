package session

import (
	"slices"
	"testing"

	"github.com/fnune/girdle/internal/profile"
)

func TestLearningModeAllowsAndRecords(t *testing.T) {
	p := &profile.Profile{Egress: profile.Egress{Allow: []profile.HostPattern{"proxy.golang.org"}}}
	strict := newLivePolicy(p, false)
	if strict.AllowsHostFor("www.kernel.org", "") || len(strict.Learned()) != 0 {
		t.Fatal("without learning mode an unknown host is refused and nothing is recorded")
	}
	learning := newLivePolicy(p, true)
	for _, h := range []string{"169.254.169.254", "10.0.0.1", "[::1]"} {
		if learning.AllowsHostFor(h, "") {
			t.Errorf("%s let through in learning mode", h)
		}
	}
	for _, h := range []string{"WWW.kernel.org", "proxy.golang.org", "www.kernel.org", "bcr.bazel.build"} {
		if !learning.AllowsHostFor(h, "") {
			t.Fatalf("%s refused in learning mode", h)
		}
	}
	if got := learning.Learned(); !slices.Equal(got, []string{"bcr.bazel.build", "www.kernel.org"}) {
		t.Fatalf("learned = %v, want only the hosts the profile does not allow", got)
	}
	learning.AllowsHostFor("js.stripe.com", "/home/u/.cache/ms-playwright/chromium-1/chrome-linux64/chrome")
	by := learning.LearnedBy()
	if !slices.Equal(by["chrome"], []string{"js.stripe.com"}) || len(by["an unidentified program"]) != 2 {
		t.Fatalf("learned by program = %v", by)
	}
}
