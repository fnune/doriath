package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
)

var errRepeatedKey = errors.New("the JSON-RPC body names a key twice")

func MCPToolCalls(body []byte) ([]string, bool) {
	tools, err := jsonRPCToolCalls(body)
	return tools, err == nil
}

func jsonRPCToolCalls(body []byte) ([]string, error) {
	var batch []json.RawMessage
	single := json.Unmarshal(body, &batch) != nil
	if single {
		batch = []json.RawMessage{body}
	}
	var tools []string
	for _, raw := range batch {
		method, name, err := jsonRPCCall(raw)
		if err != nil {
			return nil, err
		}
		if single && method == "" {
			return nil, errors.New("not JSON-RPC")
		}
		if method == "tools/call" {
			tools = append(tools, name)
		}
	}
	return tools, nil
}

func jsonRPCCall(raw json.RawMessage) (method, name string, err error) {
	message, err := jsonFields(raw)
	if err != nil {
		return "", "", err
	}
	if err := unmarshalField(message, "method", &method); err != nil {
		return "", "", err
	}
	params, ok := message["params"]
	if !ok || string(params) == "null" {
		return method, "", nil
	}
	fields, err := jsonFields(params)
	if err != nil {
		return "", "", err
	}
	return method, name, unmarshalField(fields, "name", &name)
}

func jsonFields(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.ToUpper(tok.(string)))
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if _, seen := fields[key]; seen {
			return nil, errRepeatedKey
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	return fields, nil
}

func unmarshalField(fields map[string]json.RawMessage, key string, into *string) error {
	raw, ok := fields[key]
	if !ok || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, into)
}

type mcpCalls struct {
	tools []string
	ok    bool
}

func (r Rule) matchMCP(calls func() mcpCalls) bool {
	if r.MCPNone {
		c := calls()
		return c.ok && len(c.tools) == 0
	}
	if len(r.MCPTools) == 0 {
		return true
	}
	tools := calls().tools
	if len(tools) == 0 {
		return false
	}
	matches := func(tool string) bool {
		return slices.ContainsFunc(r.MCPTools, func(glob string) bool {
			ok, _ := path.Match(glob, tool)
			return ok
		})
	}
	if r.Action == ActionAllow {
		return !slices.ContainsFunc(tools, func(t string) bool { return !matches(t) })
	}
	return slices.ContainsFunc(tools, matches)
}

func DescribeMCP(body []byte) string {
	tools, _ := MCPToolCalls(body)
	return strings.Join(tools, ", ")
}
