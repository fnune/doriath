package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/fnune/doriath/internal/profile"
)

const refCommandsLimit = 64 << 10

const unreadRefs = "refs doriath could not read"

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

func pushedRefs(r *http.Request) ([]refUpdate, bool) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.Body == nil {
		return nil, false
	}
	if !identityEncoding(r.Header.Get("Content-Encoding")) {
		return nil, true
	}
	buffered := bufio.NewReaderSize(r.Body, refCommandsLimit)
	ahead, _ := buffered.Peek(refCommandsLimit)
	r.Body = struct {
		io.Reader
		io.Closer
	}{buffered, r.Body}
	return parseRefCommands(ahead)
}

func parseRefCommands(data []byte) (refs []refUpdate, unread bool) {
	for {
		if len(data) < 4 {
			return refs, true
		}
		size, err := strconv.ParseUint(string(data[:4]), 16, 16)
		if err == nil && size == 0 {
			return refs, unread
		}
		if err != nil || size < 4 || int(size) > len(data) {
			return refs, true
		}
		line := string(data[4:size])
		data = data[size:]
		line, _, _ = strings.Cut(line, "\x00")
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "shallow":
		case len(fields) == 3 && objectID(fields[0]) && len(fields[1]) == len(fields[0]) && objectID(fields[1]) && strings.HasPrefix(fields[2], "refs/"):
			refs = append(refs, refUpdate{old: fields[0], new: fields[1], ref: fields[2]})
		default:
			unread = true
		}
	}
}

func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func pushOf(refs []refUpdate, unread bool) *profile.Push {
	if len(refs) == 0 && !unread {
		return nil
	}
	push := &profile.Push{Unread: unread}
	for _, u := range refs {
		push.Refs = append(push.Refs, u.ref)
	}
	return push
}
