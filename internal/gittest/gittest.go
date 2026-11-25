// Package gittest keeps the git configuration of the developer out of tests. Import it for its effect from a test file in each package whose tests run git.
package gittest

import "os"

func init() {
	for _, key := range []string{"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"} {
		if err := os.Setenv(key, os.DevNull); err != nil {
			panic(err)
		}
	}
}
