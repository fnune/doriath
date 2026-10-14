package profile

import (
	"encoding/json"
	"path"
	"slices"
	"strings"
)

type jsonRPCMessage struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// MCPToolCalls returns the tools that a JSON-RPC body, single or batched,
// calls with tools/call, and whether the body is JSON-RPC at all.
func MCPToolCalls(body []byte) ([]string, bool) {
	var messages []jsonRPCMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		var one jsonRPCMessage
		if json.Unmarshal(body, &one) != nil || one.Method == "" {
			return nil, false
		}
		messages = []jsonRPCMessage{one}
	}
	var tools []string
	for _, m := range messages {
		if m.Method == "tools/call" {
			tools = append(tools, m.Params.Name)
		}
	}
	return tools, true
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

// DescribeMCP names the tools a body calls, for approvals and grants.
func DescribeMCP(body []byte) string {
	tools, _ := MCPToolCalls(body)
	return strings.Join(tools, ", ")
}
