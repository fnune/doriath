package web

import (
	"context"
	"fmt"
	"hash/fnv"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/proxy"
	"github.com/fnune/doriath/internal/session"
)

const (
	answeredSince = 24 * time.Hour
	answeredShown = 20
	endedShown    = 8
	soon          = 30 * time.Second
	profileHues   = 6
)

type page struct {
	Count       string
	HasSessions bool
	Sessions    []sessionView
	Pending     []requestView
	Selected    *requestView
	Answer      *answeredView
	Answered    []answeredView
	Problem     string
	Status      statusView
}

type statusView struct {
	FirstRun bool
	Checks   []Check
	Passing  int
	Failing  bool
	Checked  string
	Ended    []endedView
}

type endedView struct {
	Session sessionView
	Ago     string
	Exit    int
	Blocked []blockedView
}

type blockedView struct {
	Host   string
	Reason string
	Count  int
	Keep   string
}

type sessionView struct {
	ID          string
	Profile     string
	Cwd         string
	Description string
	Hue         string
}

type requestView struct {
	Key       string
	ID        string
	Kind      string
	Summary   string
	Warning   string
	Details   string
	Note      string
	NoteLabel string
	Agent     string
	URL       string
	Scope     string
	Keep      string
	KeepDeny  string
	Command   string
	History   string
	Session   sessionView
	Timer     string
	Pace      string
	Fill      string
	Status    string
	Selected  bool
	Buttons   []buttonView
	ByAgent   bool
	created   time.Time
}

type answeredView struct {
	Key      string
	Selected bool
	Detail   requestView
	Summary  string
	Kind     string
	Profile  sessionView
	Verdict  string
	Label    string
	Ago      string
	By       string
}

func (s *Server) view(ctx context.Context, selected string, orOldest bool) (page, error) {
	now := s.clock.Now()
	sessions, err := s.sessions.Sessions(ctx)
	if err != nil {
		return page{Count: "Doriath cannot read the sessions"}, fmt.Errorf("read the running sessions: %w", err)
	}
	var p page
	p.HasSessions = len(sessions) > 0
	for _, sess := range sessions {
		sv := sessionView{ID: sess.ID, Profile: sess.Profile, Cwd: sess.Cwd, Description: sess.Description, Hue: hue(sess.Profile)}
		p.Sessions = append(p.Sessions, sv)
		for _, r := range sess.Requests {
			p.Pending = append(p.Pending, requestOf(r, sv, now))
		}
	}
	sort.SliceStable(p.Pending, func(i, j int) bool { return p.Pending[i].created.Before(p.Pending[j].created) })
	p.Count = count(len(sessions), len(p.Pending))

	answered, err := s.history.Answered(ctx, now.Add(-answeredSince))
	if err != nil {
		return p, fmt.Errorf("read the audit log: %w", err)
	}
	sort.SliceStable(answered, func(i, j int) bool { return answered[i].Time.After(answered[j].Time) })
	for i := range p.Pending {
		p.Pending[i].History = history(p.Pending[i].Scope, answered)
	}
	if len(answered) > answeredShown {
		answered = answered[:answeredShown]
	}
	for _, a := range answered {
		p.Answered = append(p.Answered, answeredOf(a, now))
	}
	if i := slices.IndexFunc(p.Answered, func(a answeredView) bool { return a.Key == selected }); i >= 0 && !slices.ContainsFunc(p.Pending, func(r requestView) bool { return r.Key == selected }) {
		p.Answered[i].Selected = true
		p.Answer = &p.Answered[i]
	} else {
		p.Selected = pick(p.Pending, selected, orOldest)
	}
	if p.Selected == nil && p.Answer == nil {
		if p.Status, err = s.status(ctx, now, p.HasSessions); err != nil {
			return p, err
		}
	}
	return p, nil
}

func (s *Server) status(ctx context.Context, now time.Time, running bool) (statusView, error) {
	var v statusView
	results, at := s.checks.Checks()
	for _, c := range results {
		switch c.Level {
		case "ok":
			v.Passing++
		case "problem":
			v.Failing = true
			v.Checks = append(v.Checks, c)
		default:
			v.Checks = append(v.Checks, c)
		}
	}
	sort.SliceStable(v.Checks, func(i, j int) bool { return v.Checks[i].Level == "problem" && v.Checks[j].Level != "problem" })
	if !at.IsZero() {
		v.Checked = ago(now.Sub(at))
	}
	ended, err := s.history.Ended(ctx, now.Add(-answeredSince))
	if err != nil {
		return v, fmt.Errorf("read the audit log: %w", err)
	}
	sort.SliceStable(ended, func(i, j int) bool { return ended[i].Time.After(ended[j].Time) })
	if len(ended) > endedShown {
		ended = ended[:endedShown]
	}
	for _, e := range ended {
		ev := endedView{Session: sessionView{ID: e.Session, Profile: e.Profile, Hue: hue(e.Profile)}, Ago: ago(now.Sub(e.Time)), Exit: e.Exit}
		for _, b := range e.Blocked {
			bv := blockedView{Host: session.Printable(b.Target), Reason: session.Printable(b.Reason), Count: b.Count}
			if b.Reason == proxy.ReasonNotInProfile {
				bv.Keep = fmt.Sprintf("[egress]\nallow = [%q]", b.Target)
			}
			ev.Blocked = append(ev.Blocked, bv)
		}
		v.Ended = append(v.Ended, ev)
	}
	v.FirstRun = !running && len(v.Ended) == 0
	return v, nil
}

func pick(pending []requestView, key string, orOldest bool) *requestView {
	for i := range pending {
		if pending[i].Key == key {
			pending[i].Selected = true
			return &pending[i]
		}
	}
	if !orOldest || len(pending) == 0 {
		return nil
	}
	pending[0].Selected = true
	return &pending[0]
}

func count(sessions, pending int) string {
	switch {
	case sessions == 0:
		return "No sessions running"
	case pending == 0:
		return "All quiet"
	case pending == 1:
		return "1 request waiting"
	}
	return strconv.Itoa(pending) + " requests waiting"
}

func hue(profile string) string {
	h := fnv.New32a()
	h.Write([]byte(profile))
	return "p" + strconv.Itoa(int(h.Sum32()%profileHues))
}

func requestOf(r approval.Request, sv sessionView, now time.Time) requestView {
	agent := r.Agent
	if agent == "" {
		agent = "the agent"
	}
	noteLabel := "Description"
	if r.Kind == approval.KindPath || r.Kind == approval.KindEdit {
		noteLabel = "Reason"
	}
	v := requestView{
		Key:       sv.ID + "/" + r.ID,
		ID:        r.ID,
		Kind:      string(r.Kind),
		Summary:   session.Printable(r.Summary),
		Warning:   session.Printable(r.Warning),
		Details:   session.Printable(r.Details),
		Note:      session.Printable(r.Note),
		NoteLabel: noteLabel,
		Agent:     session.Printable(agent),
		URL:       session.Printable(r.URL),
		Scope:     session.Printable(r.Scope),
		Keep:      session.Printable(r.Keep),
		KeepDeny:  session.Printable(r.KeepDeny),
		Command:   session.Printable(r.Command),
		Session:   sv,
		Buttons:   buttons(r),
		ByAgent:   r.Kind == approval.KindTool,
		created:   r.Created,
	}
	if r.Warning != "" {
		v.Keep, v.KeepDeny = "", ""
	}
	if r.Kind == approval.KindSecret {
		v.Timer, v.Pace, v.Fill = "", "parked", "0%"
		v.Status = "What needs this secret fails until it works. Try again once you have fixed its source."
		return v
	}
	waits := r.AgentWaits
	if waits.IsZero() {
		waits = r.Expires
	}
	left := waits.Sub(now).Round(time.Second)
	if left <= 0 {
		v.Timer, v.Pace, v.Fill = "parked", "parked", "0%"
		v.Status = "The agent stopped waiting and moved on. Allowing still lets its next try through."
		return v
	}
	v.Timer = clock(left)
	if left < soon {
		v.Pace = "soon"
	}
	if total := waits.Sub(r.Created); total > 0 {
		v.Fill = strconv.FormatFloat(min(1, float64(left)/float64(total))*100, 'f', 1, 64) + "%"
	}
	v.Status = "The agent is waiting for your answer, " + v.Timer + " left."
	return v
}

func clock(d time.Duration) string {
	sec := int(d.Seconds())
	if sec < 60 {
		return strconv.Itoa(sec) + "s"
	}
	return fmt.Sprintf("%d:%02d", sec/60, sec%60)
}

func answeredOf(a Answered, now time.Time) answeredView {
	sv := sessionView{ID: a.Request.Session, Profile: a.Request.Profile, Hue: hue(a.Request.Profile)}
	detail := requestOf(a.Request, sv, now)
	if a.Decision.Verdict == approval.VerdictDeny {
		detail.Keep = ""
	} else {
		detail.KeepDeny = ""
	}
	return answeredView{
		Key:     a.Request.Session + "/" + a.Request.ID,
		Detail:  detail,
		Summary: session.Printable(a.Request.Summary),
		Kind:    string(a.Request.Kind),
		Profile: sessionView{Profile: a.Request.Profile, Hue: hue(a.Request.Profile)},
		Verdict: string(a.Decision.Verdict),
		Label:   a.Request.Kind.Answered(a.Decision),
		Ago:     ago(now.Sub(a.Time)),
		By:      byLabel(a.Decision.By),
	}
}

func history(scope string, answered []Answered) string {
	if scope == "" {
		return ""
	}
	counts := map[string]int{}
	profiles := map[string]bool{}
	for _, a := range answered {
		if session.Printable(a.Request.Scope) != scope {
			continue
		}
		switch a.Decision.Verdict {
		case approval.VerdictAllow:
			counts["allowed"]++
		case approval.VerdictDeny:
			counts["denied"]++
		default:
			continue
		}
		profiles[a.Request.Profile] = true
	}
	var parts []string
	for _, verdict := range []string{"allowed", "denied"} {
		switch n := counts[verdict]; n {
		case 0:
		case 1:
			parts = append(parts, verdict+" once")
		default:
			parts = append(parts, fmt.Sprintf("%s %d times", verdict, n))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Sprintf("You %s in the last day, in profile %s.", strings.Join(parts, " and "), strings.Join(names, ", "))
}

type buttonView struct {
	Answer string
	Label  string
	Class  string
}

func buttons(r approval.Request) []buttonView {
	var out []buttonView
	for i, b := range r.Buttons() {
		class := "secondary"
		switch {
		case b.Answer == approval.AnswerDeny, b.Answer == approval.AnswerDenySession:
			class = "deny"
		case i == 0:
			class = "primary"
		}
		out = append(out, buttonView{Answer: string(b.Answer), Label: b.Label, Class: class})
	}
	return out
}

func byLabel(by string) string {
	switch by {
	case "web":
		return "here"
	case "desktop":
		return "on the desktop"
	case "cli":
		return "in a terminal"
	}
	return ""
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " min ago"
	}
	return strconv.Itoa(int(d.Hours())) + " h ago"
}
