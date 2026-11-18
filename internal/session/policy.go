package session

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

type livePolicy struct {
	*profile.Profile
	mu      sync.RWMutex
	extra   map[string]bool
	learn   bool
	learned map[string]map[string]bool
}

func newLivePolicy(p *profile.Profile, learn bool) *livePolicy {
	return &livePolicy{Profile: p, extra: map[string]bool{}, learn: learn, learned: map[string]map[string]bool{}}
}

func (l *livePolicy) AllowsHostFor(host, exe string) bool {
	if l.Profile.AllowsHostFor(host, exe) {
		return true
	}
	host = strings.ToLower(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.extra[host] {
		return true
	}
	name, port := profile.SplitTarget(host)
	if ip, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil && !publicAddr(ip) {
		return false
	}
	if port != "" || l.Refuses(host) {
		return false
	}
	if l.learn {
		if l.learned[host] == nil {
			l.learned[host] = map[string]bool{}
		}
		l.learned[host][programName(exe)] = true
	}
	return l.learn
}

func (l *livePolicy) Learned() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Sorted(maps.Keys(l.learned))
}

func (l *livePolicy) LearnedBy() map[string][]string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := map[string][]string{}
	for _, host := range slices.Sorted(maps.Keys(l.learned)) {
		for prog := range l.learned[host] {
			out[prog] = append(out[prog], host)
		}
	}
	return out
}

func programName(exe string) string {
	if exe == "" {
		return "an unidentified program"
	}
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(exe), "."), "-wrapped")
}

func (l *livePolicy) allow(host string) {
	l.mu.Lock()
	l.extra[strings.ToLower(host)] = true
	l.mu.Unlock()
}

const pendingTTL = 12 * time.Hour

// HoldHost asks you about a host the profile does not name, and waits up to
// the configured time. An allow lasts for the session, also when it comes
// after the agent stopped waiting.
func (s *Session) HoldHost(_ context.Context, host string, caller proxy.Identity) (bool, string) {
	hint := time.AfterFunc(waitHintAfter, func() { s.hintPending(caller, approval.KindHost, s.hostSummary(host)) })
	defer hint.Stop()
	d, id := s.holdHost(host, s.hostDetails(host, caller), "")
	if d.Verdict == approval.VerdictAllow {
		return true, ""
	}
	if d.Verdict == approval.VerdictDeny {
		return false, ""
	}
	return false, id
}

const maxCommandLine = 300

func (s *Session) hostDetails(host string, caller proxy.Identity) string {
	var b strings.Builder
	if note := s.req.Profile.HostNote(host); note != "" {
		fmt.Fprintf(&b, "%s: %s\n\n", host, note)
	}
	who := "A program"
	if caller.Exe != "" {
		who = fmt.Sprintf("%s (%s)", programName(caller.Exe), caller.Exe)
	}
	fmt.Fprintf(&b, "%s tried to reach %s, which the profile does not allow. An allow lasts until the session ends.%s", who, host, uploadWarning(host))
	if len(caller.Commands) > 0 {
		b.WriteString("\n\nIts command line, then each program that started it. A program writes its own command line, so read these as the agent's words:")
		for _, line := range caller.Commands {
			if len(line) > maxCommandLine {
				line = strings.ToValidUTF8(line[:maxCommandLine], "") + "…"
			}
			b.WriteString("\n  " + line)
		}
	}
	return b.String()
}

func (s *Session) hostSummary(host string) string {
	return fmt.Sprintf("Allow %s for profile %s?", host, s.req.Profile.Name)
}

func (s *Session) holdHost(host, details, reason string) (approval.Decision, string) {
	req := approval.Request{
		Session:  s.id,
		Profile:  s.req.Profile.Name,
		Kind:     approval.KindHost,
		Summary:  s.hostSummary(host),
		Details:  details,
		Note:     reason,
		Keep:     egressLines("allow", []string{host}),
		KeepDeny: egressLines("deny", []string{host}),
		Scope:    "host egress " + host,
	}
	d, id := s.manager.Hold(req, pendingTTL, s.deps.HostWait, func(d approval.Decision) {
		if d.Verdict == approval.VerdictAllow {
			s.policy.allow(host)
		}
	})
	if d.Verdict == approval.VerdictAllow {
		s.policy.allow(host)
	}
	return d, id
}

func egressLines(list string, hosts []string) string {
	quoted := make([]string, len(hosts))
	for i, h := range hosts {
		quoted[i] = strconv.Quote(h)
	}
	return fmt.Sprintf("[egress]\n%s = [%s]", list, strings.Join(quoted, ", "))
}

func publicAddr(ip netip.Addr) bool {
	ip = translatedIPv4(ip)
	return ip.IsGlobalUnicast() && !private(ip)
}

var openUploadHosts = []string{
	"amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "r2.cloudflarestorage.com",
	"digitaloceanspaces.com", "backblazeb2.com",
	"pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "file.io", "0x0.st", "termbin.com",
	"webhook.site", "requestbin.com", "pipedream.net", "beeceptor.com", "ngrok.io", "ngrok-free.app",
	"hooks.slack.com", "discord.com", "discordapp.com", "api.telegram.org",
}

func uploadWarning(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range openUploadHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return " Careful: anyone can upload to " + h + ", so allowing it lets the agent send data out."
		}
	}
	return ""
}

type RequestHostParams struct {
	Host   string `json:"host"`
	Reason string `json:"reason,omitempty"`
}

func (s *Session) requestHost(host, reason string) (RequestResult, error) {
	pattern, err := profile.ParseHostPattern(host)
	if err != nil || strings.ContainsAny(string(pattern), "*/") {
		return RequestResult{}, fmt.Errorf("%s: name one host, such as registry.npmjs.org", host)
	}
	host = string(pattern)
	if s.policy.AllowsHostFor(host, "") {
		return RequestResult{Decision: approval.Decision{Verdict: approval.VerdictAllow, Reason: "the profile already allows it"}}, nil
	}
	if s.policy.Refuses(host) {
		return RequestResult{}, fmt.Errorf("%s: the profile refuses it, so doriath does not ask the user", host)
	}
	details := fmt.Sprintf("The agent asks to reach %s, which the profile does not allow. An allow lasts until the session ends.%s", host, uploadWarning(host))
	if note := s.req.Profile.HostNote(host); note != "" {
		details = host + ": " + note + "\n\n" + details
	}
	d, id := s.holdHost(host, details, reason)
	res := RequestResult{Decision: d}
	if d.Verdict == approval.VerdictNone {
		res.Pending = id
	}
	return res, nil
}
