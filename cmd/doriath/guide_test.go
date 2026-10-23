package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGuideSkillPointsAtTheGuideCommand(t *testing.T) {
	var out bytes.Buffer
	if err := cmdGuide([]string{"skill"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "doriath guide profile") {
		t.Errorf("skill = %q", out.String())
	}
}

func TestGuideUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"profile", "extra"}} {
		if err := cmdGuide(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("guide %q = %v", args, err)
		}
	}
}
