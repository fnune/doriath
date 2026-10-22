package web

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/session"
)

const (
	answeredSince = 24 * time.Hour
	answeredShown = 20
	soon          = 30 * time.Second
	profileHues   = 6
)

type page struct {
	Count       string
	HasSessions bool
	Sessions    []sessionView
	Pending     []requestView
	Selected    *requestView
	Answered    []answeredView
	Problem     string
}

type sessionView struct {
	ID      string
	Profile string
	Cwd     string
	Hue     string
}

type requestView struct {
	Key        string
	ID         string
	Kind       string
	Summary    string
	Details    string
	Note       string
	NoteLabel  string
	Agent      string
	URL        string
	Scope      string
	Keep       string
	Session    sessionView
	Timer      string
	Pace       string
	Fill       string
	Status     string
	Selected   bool
	AllowsOnce bool
	ByAgent    bool
	created    time.Time
}

type answeredView struct {
	Summary string
	Kind    string
	Profile sessionView
	Verdict string
	Label   string
	Ago     string
	By      string
}

func (s *Server) view(ctx context.Context, selected string) (page, error) {
	now := s.clock.Now()
	sessions, err := s.sessions.Sessions(ctx)
	if err != nil {
		return page{Count: "Doriath cannot read the sessions"}, fmt.Errorf("read the running sessions: %w", err)
	}
	var p page
	p.HasSessions = len(sessions) > 0
	for _, sess := range sessions {
		sv := sessionView{ID: sess.ID, Profile: sess.Profile, Cwd: sess.Cwd, Hue: hue(sess.Profile)}
		p.Sessions = append(p.Sessions, sv)
		for _, r := range sess.Requests {
			p.Pending = append(p.Pending, requestOf(r, sv, now))
		}
	}
	sort.SliceStable(p.Pending, func(i, j int) bool { return p.Pending[i].created.Before(p.Pending[j].created) })
	p.Selected = pick(p.Pending, selected)
	p.Count = count(len(sessions), len(p.Pending))

	answered, err := s.history.Answered(ctx, now.Add(-answeredSince))
	if err != nil {
		return p, fmt.Errorf("read the audit log: %w", err)
	}
	sort.SliceStable(answered, func(i, j int) bool { return answered[i].Time.After(answered[j].Time) })
	if len(answered) > answeredShown {
		answered = answered[:answeredShown]
	}
	for _, a := range answered {
		p.Answered = append(p.Answered, answeredOf(a, now))
	}
	return p, nil
}

func pick(pending []requestView, key string) *requestView {
	for i := range pending {
		if pending[i].Key == key {
			pending[i].Selected = true
			return &pending[i]
		}
	}
	if len(pending) == 0 {
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
	if r.Kind == approval.KindPath {
		noteLabel = "Reason"
	}
	v := requestView{
		Key:        sv.ID + "/" + r.ID,
		ID:         r.ID,
		Kind:       string(r.Kind),
		Summary:    session.Printable(r.Summary),
		Details:    session.Printable(r.Details),
		Note:       session.Printable(r.Note),
		NoteLabel:  noteLabel,
		Agent:      session.Printable(agent),
		URL:        session.Printable(r.URL),
		Scope:      session.Printable(r.Scope),
		Keep:       session.Printable(r.Keep),
		Session:    sv,
		AllowsOnce: r.Kind.AllowsOnce(),
		ByAgent:    r.Kind == approval.KindTool,
		created:    r.Created,
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
	return answeredView{
		Summary: session.Printable(a.Request.Summary),
		Kind:    string(a.Request.Kind),
		Profile: sessionView{Profile: a.Request.Profile, Hue: hue(a.Request.Profile)},
		Verdict: string(a.Decision.Verdict),
		Label:   verdictLabel(a.Decision),
		Ago:     ago(now.Sub(a.Time)),
		By:      byLabel(a.Decision.By),
	}
}

func verdictLabel(d approval.Decision) string {
	switch {
	case d.Verdict == approval.VerdictAllow && d.Lasting == approval.LastingOnce:
		return "Allowed once"
	case d.Verdict == approval.VerdictAllow && d.Lasting == approval.LastingUntil:
		return "Allowed until " + d.Until.Local().Format("15:04")
	case d.Verdict == approval.VerdictAllow:
		return "Allowed for the session"
	case d.Verdict == approval.VerdictDeny:
		return "Denied"
	}
	return "No answer in time"
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
