package jailinit

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
)

const maxCommandDepth = 6

func commandChain(read func(string) ([]byte, error), procRoot string, pid int) []string {
	var lines []string
	for depth := 0; pid > 1 && depth < maxCommandDepth; depth++ {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		cmdline, err := read(filepath.Join(dir, "cmdline"))
		if err != nil {
			break
		}
		if args := strings.Fields(string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))); len(args) > 0 {
			lines = append(lines, strings.Join(args, " "))
		}
		stat, err := read(filepath.Join(dir, "stat"))
		if err != nil {
			break
		}
		pid = parentInStat(stat)
	}
	return lines
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
