package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const refCommandsLimit = 64 << 10

const zeroID = "0000000000000000000000000000000000000000"

type refUpdate struct {
	ref      string
	old, new string
}

func (u refUpdate) short() string {
	name := strings.TrimPrefix(u.ref, "refs/heads/")
	if tag, ok := strings.CutPrefix(u.ref, "refs/tags/"); ok {
		name = "tag " + tag
	}
	if strings.Trim(u.new, "0") == "" {
		return "delete " + name
	}
	return name
}

func (u refUpdate) line() string {
	switch {
	case strings.Trim(u.old, "0") == "":
		return "create " + u.ref + " at " + abbrev(u.new)
	case strings.Trim(u.new, "0") == "":
		return "delete " + u.ref + " at " + abbrev(u.old)
	}
	return "update " + u.ref + " " + abbrev(u.old) + ".." + abbrev(u.new)
}

func abbrev(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func pushedRefs(r *http.Request) []refUpdate {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.Body == nil || !identityEncoding(r.Header.Get("Content-Encoding")) {
		return nil
	}
	buffered := bufio.NewReaderSize(r.Body, refCommandsLimit)
	ahead, _ := buffered.Peek(refCommandsLimit)
	r.Body = struct {
		io.Reader
		io.Closer
	}{buffered, r.Body}
	return parseRefCommands(ahead)
}

func parseRefCommands(data []byte) []refUpdate {
	var out []refUpdate
	for len(data) >= 4 {
		size, err := strconv.ParseUint(string(data[:4]), 16, 16)
		if err != nil || size == 0 || size < 4 || int(size) > len(data) {
			break
		}
		line := string(data[4:size])
		data = data[size:]
		line, _, _ = strings.Cut(line, "\x00")
		fields := strings.Fields(line)
		if len(fields) != 3 || len(fields[0]) != len(zeroID) || len(fields[1]) != len(zeroID) || !strings.HasPrefix(fields[2], "refs/") {
			break
		}
		out = append(out, refUpdate{old: fields[0], new: fields[1], ref: fields[2]})
	}
	return out
}
