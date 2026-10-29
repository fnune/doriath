package session

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/fnune/doriath/internal/approval"
)

const (
	MethodDescribe = "session.describe"
	maxDescription = 60
	describeBurst  = 3
)

type DescribeParams struct {
	Text string `json:"text"`
}

func (s *Session) describe(text string) error {
	text = strings.Join(strings.Fields(text), " ")
	if n := utf8.RuneCountInString(text); n > maxDescription {
		return fmt.Errorf("the description has %d characters; use at most %d", n, maxDescription)
	}
	text = PrintableLine(text)
	ok, firstDropped := s.describes.allow(s.deps.Clock.Now())
	if !ok {
		if firstDropped {
			s.log.Write("describe-dropped", DescribeParams{Text: text})
		}
		return fmt.Errorf("too many descriptions: doriath takes %d at once and one more each %s", describeBurst, refillEvery)
	}
	s.mu.Lock()
	s.description = text
	s.mu.Unlock()
	s.log.Write("describe", DescribeParams{Text: text})
	return s.writeInfo()
}

func (s *Session) describedAs() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.description
}

type describedNotifier struct {
	next    approval.Notifier
	session *Session
}

func (n describedNotifier) Notify(ctx context.Context, req approval.Request, respond func(approval.Decision)) (func(), error) {
	req.SessionDescription = n.session.describedAs()
	return n.next.Notify(ctx, req, respond)
}
