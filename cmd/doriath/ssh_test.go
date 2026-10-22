package main

import (
	"strings"
	"testing"
)

func TestSSHInTheJailNamesTheHostAndTheFix(t *testing.T) {
	code, err := cmdSSH([]string{"-o", "SendEnv=GIT_PROTOCOL", "-p", "22", "git@github.com", "git-receive-pack 'fnune/home.nix.git'"})
	if code != 255 || err == nil || !strings.Contains(err.Error(), "reach github.com over SSH") || !strings.Contains(err.Error(), "add the module for github.com") {
		t.Errorf("code %d, err %v", code, err)
	}
}
