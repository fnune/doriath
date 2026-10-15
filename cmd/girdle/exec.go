package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/session"
)

func cmdExec(args []string) (int, error) {
	flags := flag.NewFlagSet("exec", flag.ContinueOnError)
	id := flags.String("session", "", "session to join (default: the only running one)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	command := flags.Args()
	if len(command) == 0 {
		command = []string{"bash"}
	}
	dir, entry, err := runningEntry(*id)
	if err != nil {
		return 1, err
	}
	filter, err := os.Open(filepath.Join(dir, "seccomp.bpf"))
	if err != nil {
		return 1, err
	}
	defer filter.Close()
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return 1, fmt.Errorf("girdle exec needs nsenter from util-linux: %w", err)
	}
	if err := entry.CheckHelper(nsenter); err != nil {
		return 1, err
	}

	argv := []string{"--target", strconv.Itoa(entry.PID), "--user", "--mount", "--net", "--pid", "--ipc", "--uts"}
	jailMapsYourIDsToThemselves := entry.UID == os.Getuid() && entry.GID == os.Getgid()
	if jailMapsYourIDsToThemselves {
		argv = append(argv, "--preserve-credentials")
	} else {
		argv = append(argv, "--setuid", strconv.Itoa(entry.UID), "--setgid", strconv.Itoa(entry.GID))
	}
	argv = append(argv, "--wd="+entryCwd(entry.Cwd), "--",
		jail.ExePath, "sandbox-exec", "--seccomp-fd", "3", "--landlock="+strconv.FormatBool(entry.Landlock))
	for _, w := range entry.Writable {
		argv = append(argv, "--writable", w)
	}
	argv = append(argv, "--")
	argv = append(argv, command...)
	cmd := exec.Command(nsenter, argv...)
	cmd.Env = entry.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{filter}
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

func runningEntry(id string) (string, session.Entry, error) {
	p, err := paths()
	if err != nil {
		return "", session.Entry{}, err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return "", session.Entry{}, err
	}
	dir, err := pickSession(sessions, id, p.Sessions())
	if err != nil {
		return "", session.Entry{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, session.EntryFile))
	if err != nil {
		return "", session.Entry{}, fmt.Errorf("the session is still starting, or was started by an older girdle: %w", err)
	}
	var entry session.Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return "", session.Entry{}, fmt.Errorf("read %s: %w", session.EntryFile, err)
	}
	if syscall.Kill(entry.PID, 0) != nil {
		return "", session.Entry{}, errors.New("the session's jail has ended")
	}
	return dir, entry, nil
}

func pickSession(sessions []liveSession, id, root string) (string, error) {
	if id != "" {
		for _, s := range sessions {
			if s.info.ID == id {
				return filepath.Join(root, id), nil
			}
		}
		return "", fmt.Errorf("no running session %s: see girdle sessions", id)
	}
	switch len(sessions) {
	case 0:
		return "", errors.New("no running sessions")
	case 1:
		return filepath.Join(root, sessions[0].info.ID), nil
	}
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = s.info.ID
	}
	return "", fmt.Errorf("several sessions are running (%s): pick one with --session", strings.Join(ids, ", "))
}

func entryCwd(sessionCwd string) string {
	wd, err := os.Getwd()
	if err == nil && (wd == sessionCwd || strings.HasPrefix(wd, sessionCwd+"/")) {
		return wd
	}
	return sessionCwd
}
