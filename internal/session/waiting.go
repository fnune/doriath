package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/proxy"
)

// waitHintAfter keeps the line off requests that you answer within seconds.
const waitHintAfter = 5 * time.Second

// Waiting writes to the standard error of the program whose request the
// proxy holds. The proxy cannot reach it any other way: the connection
// carries the program's own TLS or HTTP bytes, and a program that waits for
// a response prints nothing.
func (s *Session) Waiting(caller proxy.Identity, summary string) {
	for _, req := range s.manager.Pending() {
		if req.Kind == approval.KindHTTP && req.Session == s.id && req.Summary == summary {
			s.peers.writeToStderr(caller.PID, waitingLine(req, s.deps.Clock.Now()))
			return
		}
	}
}

func waitingLine(req approval.Request, now time.Time) string {
	return fmt.Sprintf("doriath: waiting for approval of %s. Do not retry: the request stays open for %s. The user answers with %s or on the approvals page.\n",
		PrintableLine(req.Summary), req.Expires.Sub(now).Round(time.Second), cli.Code(cli.Line("approvals", "allow", req.ID)))
}

// writeToStderr writes line to descriptor 2 of the jail process with pid
// jailPID. It is best effort: the descriptor can be a socket, a closed pipe
// or gone.
func (h *hostPeers) writeToStderr(jailPID int, line string) {
	hostPID := h.hostPID(jailPID)
	if hostPID == 0 {
		return
	}
	stderr := filepath.Join(h.proc, strconv.Itoa(hostPID), "fd", "2")
	if h.isSessionTerminal(stderr) {
		return
	}
	// Opening through /proc starts at offset 0, which would overwrite a file
	// that the program redirected its stderr to.
	f, err := os.OpenFile(stderr, os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// isSessionTerminal reports whether path is the terminal that the jail was
// started on. The agent's interface draws there, and a stray line would
// garble it. bubblewrap's reaper keeps the session's standard streams.
func (h *hostPeers) isSessionTerminal(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	for fd := range 3 {
		own, err := os.Stat(filepath.Join(h.proc, strconv.Itoa(int(h.init.Load())), "fd", strconv.Itoa(fd)))
		if err == nil && os.SameFile(info, own) {
			return true
		}
	}
	return false
}

// hostPID finds the process that the jail's init names jailPID. Only a
// process in the jail's own pid namespace can have that number there.
func (h *hostPeers) hostPID(jailPID int) int {
	reaper := int(h.init.Load())
	if reaper == 0 || jailPID <= 0 {
		return 0
	}
	jailNS, err := os.Readlink(filepath.Join(h.proc, strconv.Itoa(reaper), "ns", "pid"))
	if err != nil {
		return 0
	}
	entries, err := os.ReadDir(h.proc)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(h.proc, e.Name())
		if ns, err := os.Readlink(filepath.Join(dir, "ns", "pid")); err != nil || ns != jailNS {
			continue
		}
		if innermostPID(dir) == jailPID {
			return pid
		}
	}
	return 0
}

func innermostPID(procDir string) int {
	data, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		pids := strings.Fields(fields)
		if len(pids) == 0 {
			return 0
		}
		pid, _ := strconv.Atoi(pids[len(pids)-1])
		return pid
	}
	return 0
}
