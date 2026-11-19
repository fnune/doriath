package proxy

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

type described struct {
	action   string
	facts    []approval.Fact
	link     approval.Link
	commands []string
}

type httpRequest struct {
	rule      profile.Rule
	matched   bool
	method    string
	host      string
	path      string
	repo      string
	operation string
	body      []byte
	refs      []refUpdate
	unread    bool
	caller    Identity
}

func describe(q httpRequest) described {
	d := described{action: q.action(), commands: q.caller.Commands}
	values := profile.TemplateValues{Segments: profile.PathSegments(q.path), Ref: q.singleRef()}
	if q.matched && q.rule.Link != nil {
		if u, ok := q.rule.Link.URL.Expand(values, escapePath); ok {
			d.link = approval.Link{Label: q.rule.Link.Label, URL: u}
		}
	}
	if subject := q.subject(values); subject != "" {
		d.facts = append(d.facts, approval.Fact{Label: "About", Value: subject, URL: d.link.URL})
	}
	for _, u := range q.refs {
		d.facts = append(d.facts, approval.Fact{Label: "Change", Value: u.line()})
	}
	for _, a := range q.arguments() {
		d.facts = append(d.facts, approval.Fact{Label: a.Name, Value: a.Value})
	}
	if q.caller.Exe != "" {
		d.facts = append(d.facts, approval.Fact{Label: "Program", Value: ProgramName(q.caller.Exe)})
	}
	return d
}

func (q httpRequest) action() string {
	if q.matched && q.rule.MCPServer != "" {
		if tools, _ := profile.MCPToolCalls(q.body); len(tools) == 1 {
			return profile.Humanize(strings.TrimPrefix(tools[0], q.rule.MCPServer+"-"))
		}
	}
	if q.matched && q.rule.Summary != "" {
		return q.rule.Summary
	}
	if _, field := profile.GraphQLField(q.body); field != "" {
		return profile.Humanize(field)
	}
	action := q.method + " " + q.path
	if q.repo != "" && len(q.path) > len(q.repo) && strings.EqualFold(q.path[:len(q.repo)], q.repo) {
		action = q.method + " " + q.path[len(q.repo):]
	}
	if q.operation != "" {
		action += " " + q.operation
	}
	return action
}

func (q httpRequest) subject(values profile.TemplateValues) string {
	if q.matched {
		if s, ok := q.rule.Subject.Expand(values, func(s string) string { return s }); ok {
			return s
		}
	}
	var parts []string
	switch {
	case q.repo != "":
		parts = append(parts, repositoryName(q.repo))
	case q.matched && q.rule.MCPServer != "":
		parts = append(parts, q.rule.MCPServer)
	case q.host != "":
		parts = append(parts, q.host)
	}
	var names []string
	for _, u := range q.refs {
		names = append(names, u.short())
	}
	if q.unread {
		names = append(names, unreadRefs)
	}
	if len(names) > 0 {
		parts = append(parts, strings.Join(names, ", "))
	}
	return strings.Join(parts, " ")
}

func (q httpRequest) singleRef() string {
	if len(q.refs) != 1 || q.unread || q.refs[0].deletes() {
		return ""
	}
	return strings.TrimPrefix(strings.TrimPrefix(q.refs[0].ref, "refs/heads/"), "refs/tags/")
}

func (q httpRequest) arguments() []profile.Argument {
	if profile.DescribeGraphQL(q.body) != "" {
		return profile.GraphQLVariables(q.body)
	}
	if tools, ok := profile.MCPToolCalls(q.body); ok && len(tools) > 0 {
		return profile.MCPArguments(q.body)
	}
	return profile.JSONArguments(q.body)
}

func escapePath(s string) string {
	parts := strings.Split(s, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func repositoryName(repo string) string {
	return repo[strings.LastIndexByte(repo, '/')+1:]
}

func ProgramName(exe string) string {
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(exe), "."), "-wrapped")
}
