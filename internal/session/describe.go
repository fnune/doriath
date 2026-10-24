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
	if len(st.Unavailable) > 0 {
		b.WriteString("Secrets that doriath cannot read, so these fail until the user fixes them on the host. doriath tries again at most every 30 seconds:\n")
		for _, m := range st.Unavailable {
			fmt.Fprintf(&b, "  - %s (%s): %s\n", m.Secret, strings.Join(m.Users, ", "), m.Error)
		}
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
		"To wait for the answer, run `doriath request wait HOST` in the background if you can, then try again. " +
		"To write paths that are read-only here, or folders that this jail does not show, first plan every change you will make, then run `doriath request write PATH --reason TEXT` once, for the narrowest file or directory that covers them all. It asks the user on the approvals page, waits, and keeps PATH writable until the session ends. " +
		"To read a folder that this jail does not show, run `doriath request read PATH --reason TEXT`. " +
		"When a secret is unavailable, doriath shows the user a card on the approvals page. Wait for it with the command in the error. Do not ask the user to run commands on their machine. " +
		"Each `doriath request edit` asks the user again, so use it only where `doriath request write` refuses, such as .git/config when git or jj cannot write it: write the whole new content to a file and run `doriath request edit PATH --reason TEXT < FILE`, then run the git or jj command again. git here records a branch's upstream itself, and asks the user before `git remote add`. " +
		"Errors that start with \"doriath:\" come from this sandbox. Do not look for another way around a block. " +
		"If the user denies a request, tell them what was blocked and why the task needs it. Run `doriath status` to see this again.\n")
	return b.String()
}
