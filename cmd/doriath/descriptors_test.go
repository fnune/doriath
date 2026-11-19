package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

const descriptorChild = "DORIATH_TEST_DESCRIPTOR_CHILD"

func TestInheritedDescriptorsAreClosedOnExec(t *testing.T) {
	if os.Getenv(descriptorChild) != "" {
		flags, err := unix.FcntlInt(3, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			t.Fatalf("setup: descriptor 3 flags %d, %v", flags, err)
		}
		closeInheritedOnExec()
		flags, err = unix.FcntlInt(3, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("descriptor 3 stays open across exec: flags %d, %v", flags, err)
		}
		if flags, _ := unix.FcntlInt(1, unix.F_GETFD, 0); flags&unix.FD_CLOEXEC != 0 {
			t.Fatal("standard output is closed on exec")
		}
		return
	}
	f, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), descriptorChild+"=1")
	cmd.ExtraFiles = []*os.File{f}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestInternalCommandsKeepTheirDescriptors(t *testing.T) {
	for _, c := range []string{"__promote", "__sandbox-exec", "__connect"} {
		if !isInternalCommand([]string{c}) {
			t.Errorf("%s is not internal", c)
		}
	}
	if isInternalCommand([]string{"run"}) || isInternalCommand(nil) {
		t.Error("a user command is internal")
	}
}
