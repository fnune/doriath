package session

import (
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcstools"
)

type signingTool struct{ setting string }

func (signingTool) Name() string                       { return "vcs" }
func (t signingTool) HostSigns() string                { return t.setting }
func (signingTool) Jail(vcstools.Jail) vcstools.Config { return vcstools.Config{} }

func TestASessionThatCouldNotSignWhatYourConfigSignsDoesNotStart(t *testing.T) {
	signs := []vcstools.Tool{signingTool{}, signingTool{setting: "signing.behavior = own"}}
	err := CheckSigning(&profile.Profile{Name: "default"}, signs)
	if err == nil || !strings.Contains(err.Error(), "signing.behavior = own") || !strings.Contains(err.Error(), "enable = false") {
		t.Errorf("err = %v", err)
	}
	for _, p := range []*profile.Profile{{Name: "a", SigningKey: "signing"}, {Name: "b", Unsigned: true}} {
		if err := CheckSigning(p, signs); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
	if err := CheckSigning(&profile.Profile{Name: "c"}, []vcstools.Tool{signingTool{}}); err != nil {
		t.Errorf("a host that signs nothing: %v", err)
	}
}
