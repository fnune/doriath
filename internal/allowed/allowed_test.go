package allowed

import (
	"os"
	"slices"
	"testing"
)

func TestAStoreKeepsWhatYouAllowed(t *testing.T) {
	s := NewStore(t.TempDir())
	key := Key{Profile: "app+repo:dev", Repository: "/home/u/src/app"}
	if _, seen, err := s.Grants(key); err != nil || seen {
		t.Fatalf("seen %v, err %v before any answer", seen, err)
	}
	if err := s.Allow(key, []string{"Egress.Allow: b.example", "Egress.Allow: a.example"}); err != nil {
		t.Fatal(err)
	}
	got, seen, err := s.Grants(key)
	if err != nil || !seen || !slices.Equal(got, []string{"Egress.Allow: a.example", "Egress.Allow: b.example"}) {
		t.Fatalf("grants %q, seen %v, err %v", got, seen, err)
	}
}

func TestEachRepositoryAsksForItself(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := s.Allow(Key{Profile: "app+repo:dev", Repository: "/home/u/src/app"}, []string{"x"}); err != nil {
		t.Fatal(err)
	}
	for _, other := range []Key{{Profile: "app+repo:dev", Repository: "/home/u/src/other"}, {Profile: "app+repo:dev"}, {Profile: "app"}} {
		if _, seen, _ := s.Grants(other); seen {
			t.Errorf("%+v counts as allowed", other)
		}
	}
}

func TestAStoreIsPrivateToYou(t *testing.T) {
	dir := t.TempDir() + "/profiles"
	if err := NewStore(dir).Allow(Key{Profile: "app"}, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v, err %v", info.Mode(), err)
	}
}
