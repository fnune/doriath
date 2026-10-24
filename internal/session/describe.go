package session

import (
	"fmt"
	"strings"
)

// Describe tells the agent what the jail allows and how to ask for more.
func (st Status) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "This session runs in doriath profile %q (session %s).\n", st.Profile, st.Session)
	list := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s:\n", title)
		for _, it := range items {
			fmt.Fprintf(&b, "  - %s\n", it)
		}
	}
	list("Writable paths", st.Writable)
	list("Read-only paths", st.ReadOnly)
	list("Reachable hosts (HTTPS through the proxy)", st.Hosts)
	for _, h := range st.Intercepted {
		cred := ""
		if h.Credential {
			cred = ", with a credential the proxy adds"
		}
		fmt.Fprintf(&b, "Host %s (default %s%s):\n", h.Host, h.Default, cred)
		for _, r := range h.Rules {
			line := fmt.Sprintf("%s %s: %s", r.Method, r.Path, r.Action)
			if r.Summary != "" {
				line += " (" + r.Summary + ")"
			}
			fmt.Fprintf(&b, "  - %s\n", line)
		}
	}
	if len(st.Ports) > 0 {
		ports := make([]string, len(st.Ports))
		for i, p := range st.Ports {
			ports[i] = fmt.Sprint(p)
		}
		fmt.Fprintf(&b, "Local ports: %s\n", strings.Join(ports, ", "))
	}
	if st.Signing {
		b.WriteString("Commits are signed by an agent key through SSH_AUTH_SOCK. It signs git commits only.\n")
	}
	if st.Podman {
		b.WriteString("Containers: podman through CONTAINER_HOST. Containers share this network and the proxy.\n")
	}
	if st.Pending > 0 {
		fmt.Fprintf(&b, "Requests waiting for the user: %d\n", st.Pending)
	}
	if len(st.Denied) > 0 {
		b.WriteString("Blocked so far:\n")
		for _, d := range st.Denied {
			fmt.Fprintf(&b, "  - %s: %s (%d times)\n", d.Host, d.Reason, d.Count)
		}
	}
	b.WriteString("To reach a host that is not listed, make the request: doriath then asks the user whether to allow the host. " +
		"Do not decide that a host is unreachable before you try it. " +
		"The first request fails, often only as \"CONNECT tunnel failed, response 403\". " +
		"To wait for the answer, run doriath request wait HOST, in the background if you can, then try again. " +
		"To write a path that is read-only here, run doriath request write PATH --reason TEXT, which asks the user and waits. " +
		"To change one read-only file, such as .git/config when git or jj cannot write it, write the whole new content to a file and run doriath request edit PATH --reason TEXT < FILE, then run the git or jj command again; upstream tracking changes at once. " +
		"Errors that start with \"doriath:\" come from this sandbox. Do not look for another way around a block. " +
		"If the user denies a request, tell them what was blocked and why the task needs it. Run doriath status to see this again.\n")
	return b.String()
}
