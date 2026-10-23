package cli

import "testing"

func TestLine(t *testing.T) {
	cases := map[string][]string{
		"doriath approvals grant --session a1 /home/me/x": {"approvals", "grant", "--session", "a1", "/home/me/x"},
		`doriath exec -- sh -c 'echo "$HOME"'`:            {"exec", "--", "sh", "-c", `echo "$HOME"`},
		`doriath request write '/tmp/it'\''s here'`:       {"request", "write", "/tmp/it's here"},
		"doriath exec ''": {"exec", ""},
	}
	for want, args := range cases {
		if got := Line(args...); got != want {
			t.Errorf("Line(%q) = %s, want %s", args, got, want)
		}
	}
}
