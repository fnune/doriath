package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Template is a rule's text with placeholders: {1} to {9} for the segments
// of the request path, and {ref} for the branch or tag that a push updates.
type Template string

type TemplateValues struct {
	Segments []string
	Ref      string
}

var placeholder = regexp.MustCompile(`\{([^{}]*)\}`)

func ParseTemplate(s string) (Template, error) {
	for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
		if !validPlaceholder(m[1]) {
			return "", fmt.Errorf("%q: unknown placeholder {%s}: want {1} to {9} or {ref}", s, m[1])
		}
	}
	return Template(s), nil
}

func validPlaceholder(name string) bool {
	if name == "ref" {
		return true
	}
	n, err := strconv.Atoi(name)
	return err == nil && n >= 1 && n <= 9
}

// ParseLinkTemplate refuses a placeholder in the scheme or the host, so that
// the request cannot choose the site that the link opens.
func ParseLinkTemplate(s string) (Template, error) {
	t, err := ParseTemplate(s)
	if err != nil {
		return "", err
	}
	rest, ok := strings.CutPrefix(s, "https://")
	slash := strings.IndexByte(rest, '/')
	if !ok || slash <= 0 || strings.Contains(rest[:slash], "{") {
		return "", fmt.Errorf("%q: want an https:// URL with a fixed host, such as https://github.com/{2}/{3}/pull/{5}", s)
	}
	if _, err := url.Parse(placeholder.ReplaceAllString(s, "x")); err != nil {
		return "", fmt.Errorf("%q: %w", s, err)
	}
	return t, nil
}

// Expand gives false when a placeholder has no value, so that a rule never
// shows a fact or a link with a hole in it.
func (t Template) Expand(v TemplateValues, escape func(string) string) (string, bool) {
	ok := true
	out := placeholder.ReplaceAllStringFunc(string(t), func(m string) string {
		name := m[1 : len(m)-1]
		value := v.Ref
		if name != "ref" {
			n, _ := strconv.Atoi(name)
			value = ""
			if n <= len(v.Segments) {
				value = v.Segments[n-1]
			}
		}
		if value == "" {
			ok = false
		}
		return escape(value)
	})
	return out, ok && t != ""
}

func PathSegments(path string) []string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	var out []string
	for s := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		out = append(out, strings.TrimSuffix(s, ".git"))
	}
	return out
}

// Humanize turns an operation or tool name, such as requestReviewsByLogin,
// save_issue or update-page, into words: "Request reviews by login".
func Humanize(name string) string {
	var words []string
	var word []rune
	flush := func() {
		if len(word) > 0 {
			words = append(words, strings.ToLower(string(word)))
			word = nil
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/' || unicode.IsSpace(r):
			flush()
			continue
		case unicode.IsUpper(r) && len(word) > 0 && (unicode.IsLower(word[len(word)-1]) || i+1 < len(runes) && unicode.IsLower(runes[i+1])):
			flush()
		}
		word = append(word, r)
	}
	flush()
	if len(words) == 0 {
		return name
	}
	s := strings.Join(words, " ")
	first, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(first)) + s[size:]
}

type Argument struct {
	Name  string
	Value string
}

const (
	maxArguments     = 6
	maxArgumentValue = 80
)

// GraphQLVariables lists the variables of a GraphQL request, where the
// values that a mutation changes usually are.
func GraphQLVariables(body []byte) []Argument {
	var req struct {
		Variables json.RawMessage `json:"variables"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil
	}
	return arguments(req.Variables)
}

// MCPArguments lists the arguments of an MCP request that calls one tool.
func MCPArguments(body []byte) []Argument {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &req) != nil || req.Method != "tools/call" {
		return nil
	}
	return arguments(req.Params.Arguments)
}

// JSONArguments lists the fields of a JSON object body.
func JSONArguments(body []byte) []Argument {
	return arguments(body)
}

// GraphQLField is the one field that a GraphQL request selects at its top
// level, or "" when it selects several.
func GraphQLField(body []byte) (GraphQLOperation, string) {
	ops, ok := parseGraphQL(body)
	if !ok || len(ops) != 1 || len(ops[0].Fields) != 1 {
		return "", ""
	}
	return ops[0].Type, ops[0].Fields[0]
}

type field struct {
	name  string
	value json.RawMessage
}

func arguments(raw json.RawMessage) []Argument {
	fields, ok := objectFields(raw)
	for ok && len(fields) == 1 {
		inner, isObject := objectFields(fields[0].value)
		if !isObject {
			break
		}
		fields = inner
	}
	var out []Argument
	for _, f := range fields {
		if len(out) == maxArguments {
			break
		}
		var v any
		if json.Unmarshal(f.value, &v) != nil {
			continue
		}
		if s := argumentValue(v); s != "" {
			out = append(out, Argument{Name: f.name, Value: s})
		}
	}
	return out
}

func objectFields(raw json.RawMessage) ([]field, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var fields []field
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		fields = append(fields, field{name: name, value: value})
	}
	return fields, true
}

func argumentValue(v any) string {
	var s string
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		s = v
	case bool, float64:
		s = fmt.Sprint(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			switch item.(type) {
			case string, bool, float64:
				parts = append(parts, fmt.Sprint(item))
			default:
				raw, _ := json.Marshal(v)
				return shorten(string(raw))
			}
		}
		s = strings.Join(parts, ", ")
	default:
		raw, _ := json.Marshal(v)
		s = string(raw)
	}
	return shorten(s)
}

func shorten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= maxArgumentValue {
		return s
	}
	r := []rune(s)
	return string(r[:maxArgumentValue]) + "…"
}
