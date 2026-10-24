package cli

import "testing"

func TestLine(t *testing.T) {
	cases := map[string][]string{
		"doriath forward --session a1 /home/me/x":   {"forward", "--session", "a1", "/home/me/x"},
		`doriath exec -- sh -c 'echo "$HOME"'`:      {"exec", "--", "sh", "-c", `echo "$HOME"`},
		`doriath request write '/tmp/it'\''s here'`: {"request", "write", "/tmp/it's here"},
		"doriath exec ''":                           {"exec", ""},
	}
	for want, args := range cases {
		if got := Line(args...); got != want {
			t.Errorf("Line(%q) = %s, want %s", args, got, want)
		}
	}
}

func TestWordsQuotesOnlyWhatTheShellWouldSplit(t *testing.T) {
	got := Words("sh", "-c", `bw get password github --session "$(bw unlock --raw)"`)
	if want := `sh -c 'bw get password github --session "$(bw unlock --raw)"'`; got != want {
		t.Errorf("Words = %s, want %s", got, want)
	}
}
