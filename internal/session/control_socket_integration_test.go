//go:build integration

package session_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestAMountedRuntimeDirectoryDoesNotLetTheAgentAnswerItsOwnRequests(t *testing.T) {
	e := newEnv(t)
	sessions := filepath.Join(e.paths.Runtime, "sessions")
	extra := fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n", sessions)
	script := `python3 - <<'PY'
import os, socket, json
sdir = os.path.join(` + fmt.Sprintf("%q", sessions) + `, os.environ["DORIATH_SESSION"])
def call(sock, method, params=None):
    s = socket.socket(socket.AF_UNIX); s.connect(sock)
    try:
        s.sendall((json.dumps({"method": method, "params": params or {}}) + "\n").encode())
        line = s.makefile().readline()
    except ConnectionError:
        return {}
    return json.loads(line) if line else {}
r = call(os.environ["DORIATH_BROKER"], "host.request", {"host": "evil.example", "reason": "x"})
pending = r["result"]["pending"]
control = os.path.join(sdir, "control.sock")
try:
    d = call(control, "approvals.decide", {"id": pending, "decision": {"verdict": "allow", "lasting": "session", "by": "agent"}})
except OSError as e:
    print("NOT REACHED: the connection to the control socket failed:", e)
    raise SystemExit(0)
if d.get("result") is not None:
    print("ESCAPED: the agent approved its own request:", d)
elif d:
    print("NOT REFUSED BY THE PEER CHECK:", d)
else:
    print("REFUSED")
PY
exit 0
`
	code, out := e.run(e.profile(extra), script, nil)
	if code != 0 || !strings.Contains(out, "REFUSED") || strings.Contains(out, "NOT ") || strings.Contains(out, "ESCAPED") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
