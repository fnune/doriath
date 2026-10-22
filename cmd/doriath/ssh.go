package main

import (
	"fmt"
	"strings"
)

var sshOptionsWithValue = map[string]bool{"-o": true, "-p": true, "-i": true, "-l": true, "-F": true, "-J": true}

func cmdSSH(args []string) (int, error) {
	host := ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case sshOptionsWithValue[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			host = a[strings.LastIndex(a, "@")+1:]
			i = len(args)
		}
	}
	if host == "" {
		host = "the host"
	}
	return 255, fmt.Errorf("git tried to reach %s over SSH, which has no route out of the jail. A forge's module sends the SSH remotes of its host over HTTPS through the proxy: add the module for %s to the profile, or push from outside the jail", host, host)
}
