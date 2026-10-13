package profile

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

type GraphQLOperation string

const (
	GraphQLQuery        GraphQLOperation = "query"
	GraphQLMutation     GraphQLOperation = "mutation"
	GraphQLSubscription GraphQLOperation = "subscription"
)

// GraphQLRule narrows a rule to GraphQL requests whose every operation has
// this type and, when Fields is set, selects only these top-level fields.
type GraphQLRule struct {
	Operation GraphQLOperation
	Fields    []string
}

func (g GraphQLRule) String() string {
	s := "graphql " + string(g.Operation)
	if len(g.Fields) > 0 {
		s += " " + strings.Join(g.Fields, ",")
	}
	return s
}

func (g GraphQLRule) match(ops []graphQLOperation) bool {
	if len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		if op.Type != g.Operation {
			return false
		}
		if g.Fields == nil {
			continue
		}
		for _, f := range op.Fields {
			if !slices.Contains(g.Fields, f) {
				return false
			}
		}
	}
	return true
}

type graphQLOperation struct {
	Type   GraphQLOperation
	Fields []string
}

// maxGraphQLTokens bounds the parser's recursion, so that a deeply nested
// query cannot exhaust the proxy's stack. gqlgen uses the same default.
const maxGraphQLTokens = 15000

// parseGraphQL returns every operation in a GraphQL request body, single or
// batched. It reports false when any part of the body cannot be read, so a
// rule never matches a request it does not fully understand.
func parseGraphQL(body []byte) (ops []graphQLOperation, ok bool) {
	defer func() {
		if recover() != nil {
			ops, ok = nil, false
		}
	}()
	queries, ok := graphQLQueries(body)
	if !ok {
		return nil, false
	}
	for _, q := range queries {
		doc, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: q}, maxGraphQLTokens)
		if err != nil || len(doc.Operations) == 0 || duplicateFragments(doc) {
			return nil, false
		}
		x := expander{doc: doc, done: map[string][]string{}, active: map[string]bool{}}
		for _, op := range doc.Operations {
			fields, ok := x.fields(op.SelectionSet)
			if !ok {
				return nil, false
			}
			ops = append(ops, graphQLOperation{Type: GraphQLOperation(op.Operation), Fields: fields})
		}
	}
	return ops, len(ops) > 0
}

// duplicateFragments catches a document that defines a fragment twice, since
// the spread could then resolve to a definition other than the one checked.
func duplicateFragments(doc *ast.QueryDocument) bool {
	seen := map[string]bool{}
	for _, f := range doc.Fragments {
		if seen[f.Name] {
			return true
		}
		seen[f.Name] = true
	}
	return false
}

// DescribeGraphQL names the operation types and top-level fields of a
// GraphQL body, or returns "" when the body is not one.
func DescribeGraphQL(body []byte) string {
	ops, ok := parseGraphQL(body)
	if !ok {
		return ""
	}
	parts := make([]string, len(ops))
	for i, op := range ops {
		parts[i] = string(op.Type) + " " + strings.Join(op.Fields, ",")
	}
	return strings.Join(parts, "; ")
}

// graphQLQueries returns the query text of each request in a body. Every key
// that folds to "query" counts, because decoders differ on duplicate and
// differently cased keys and the server may read any of them.
func graphQLQueries(body []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	var queries []string
	switch tok {
	case json.Delim('{'):
		q, ok := requestQueries(dec)
		if !ok {
			return nil, false
		}
		queries = q
	case json.Delim('['):
		for dec.More() {
			if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
				return nil, false
			}
			q, ok := requestQueries(dec)
			if !ok {
				return nil, false
			}
			queries = append(queries, q...)
		}
		if _, err := dec.Token(); err != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return queries, len(queries) > 0
}

// requestQueries reads the rest of one request object, whose opening brace
// the caller consumed. A request without query text, such as a persisted
// query sent by hash, cannot be checked.
func requestQueries(dec *json.Decoder) ([]string, bool) {
	var queries []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := tok.(string)
		if !ok {
			return nil, false
		}
		if !strings.EqualFold(key, "query") {
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return nil, false
			}
			continue
		}
		var q *string
		if dec.Decode(&q) != nil || q == nil || *q == "" {
			return nil, false
		}
		queries = append(queries, *q)
	}
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	return queries, len(queries) > 0
}

// expander lists the top-level fields of a selection set, through inline
// fragments and fragment spreads. Each named fragment is expanded once, so
// fragments that spread each other many times cannot blow up the work.
type expander struct {
	doc    *ast.QueryDocument
	done   map[string][]string
	active map[string]bool
}

func (x expander) fields(set ast.SelectionSet) ([]string, bool) {
	var out []string
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			out = append(out, s.Name)
		case *ast.InlineFragment:
			f, ok := x.fields(s.SelectionSet)
			if !ok {
				return nil, false
			}
			out = append(out, f...)
		case *ast.FragmentSpread:
			f, ok := x.fragment(s.Name)
			if !ok {
				return nil, false
			}
			out = append(out, f...)
		default:
			return nil, false
		}
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func (x expander) fragment(name string) ([]string, bool) {
	if f, ok := x.done[name]; ok {
		return f, true
	}
	def := x.doc.Fragments.ForName(name)
	if def == nil || x.active[name] {
		return nil, false
	}
	x.active[name] = true
	f, ok := x.fields(def.SelectionSet)
	delete(x.active, name)
	if !ok {
		return nil, false
	}
	x.done[name] = f
	return f, true
}
