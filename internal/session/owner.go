package session

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fnune/doriath/internal/vcs"
)

func processOwner(procRoot string, pid int) (vcs.Owner, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(path)
	if err != nil {
		return vcs.Owner{}, err
	}
	const startTimeAfterName = 19
	name := strings.LastIndex(string(data), ") ")
	if name < 0 {
		return vcs.Owner{}, errors.New("unexpected format of " + path)
	}
	fields := strings.Fields(string(data)[name+2:])
	if len(fields) <= startTimeAfterName {
		return vcs.Owner{}, errors.New("unexpected format of " + path)
	}
	start, err := strconv.ParseUint(fields[startTimeAfterName], 10, 64)
	if err != nil {
		return vcs.Owner{}, err
	}
	return vcs.Owner{PID: pid, Start: start}, nil
}

// Running reports whether the doriath process that owns rec still runs.
func Running(procRoot string, rec *vcs.Record) bool {
	if rec.Owner.PID == 0 {
		return false
	}
	now, err := processOwner(procRoot, rec.Owner.PID)
	return err == nil && now == rec.Owner
}
