package jailinit

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
)

const maxCommandDepth = 6

func commandChain(read func(string) ([]byte, error), procRoot string, pid, self int) []string {
	var lines []string
	for depth := 0; pid > 1 && pid != self && depth < maxCommandDepth; depth++ {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		cmdline, err := read(filepath.Join(dir, "cmdline"))
		if err != nil {
			break
		}
		if line := commandLine(cmdline); line != "" {
			lines = append(lines, line)
		}
		stat, err := read(filepath.Join(dir, "stat"))
		if err != nil {
			break
		}
		pid = parentInStat(stat)
	}
	return lines
}

func commandLine(cmdline []byte) string {
	trimmed := strings.TrimSuffix(string(cmdline), "\x00")
	if trimmed == "" {
		return ""
	}
	var args []string
	for arg := range strings.SplitSeq(trimmed, "\x00") {
		args = append(args, shellQuote(arg))
	}
	return strings.Join(args, " ")
}

func shellQuote(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\n'\"\\$`;&|<>(){}*?[]#~") {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

func parentInStat(stat []byte) int {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}
