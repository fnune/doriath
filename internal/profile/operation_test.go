package profile

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

const operationHost = `
[[http]]
host = "cloudformation.us-east-1.amazonaws.com"
default = "approve"
operation = { header = "X-Amz-Target", form = "Action" }

[[http.rules]]
method = "POST"
path = "/"
form = { Action = "Describe*" }
action = "allow"

[[http.rules]]
method = "POST"
path = "/"
header = "X-Amz-Target"
header_glob = "DynamoDB_*.DeleteTable"
action = "deny"
`

func operationRules(t *testing.T) HTTPHost {
	t.Helper()
	p, err := loader(fstest.MapFS{"p.toml": file(operationHost)}, fstest.MapFS{}).Load("p")
	if err != nil {
		t.Fatal(err)
	}
	return p.HTTP[0]
}

func TestRulesMatchTheOperationInAFormOrAHeader(t *testing.T) {
	h := operationRules(t)
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"}}
	target := func(v string) http.Header { return http.Header{"X-Amz-Target": {v}} }
	for name, c := range map[string]struct {
		query  url.Values
		header http.Header
		body   string
		want   Action
	}{
		"a read in the body":     {nil, form, "Action=DescribeStacks&Version=2010-05-15", ActionAllow},
		"a read in the query":    {url.Values{"Action": {"DescribeStackEvents"}}, http.Header{}, "", ActionAllow},
		"a delete":               {nil, form, "Action=DeleteStack", ActionApprove},
		"a form field in JSON":   {nil, http.Header{"Content-Type": {"application/json"}}, `{"Action":"DescribeStacks"}`, ActionApprove},
		"a header that matches":  {nil, target("DynamoDB_20120810.DeleteTable"), "", ActionDeny},
		"a header that does not": {nil, target("DynamoDB_20120810.DescribeTable"), "", ActionApprove},
		"the action named twice": {url.Values{"Action": {"DeleteStack"}}, form, "Action=DescribeStacks", ActionAllow},
		"no operation at all":    {nil, http.Header{}, "", ActionApprove},
	} {
		if r, _ := h.DecideWithQuery("POST", "/", c.query, c.header, []byte(c.body)); r.Action != c.want {
			t.Errorf("%s: %s, want %s", name, r.Action, c.want)
		}
	}
	if !h.NeedsFormBody(form) || h.NeedsFormBody(http.Header{"Content-Type": {"application/octet-stream"}}) {
		t.Error("only a form body needs reading for the operation")
	}
}

func TestTheOperationNamesWhatAnApprovalCovers(t *testing.T) {
	h := operationRules(t)
	got := h.OperationOf(nil, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "X-Amz-Target": {"X.Y"}}, []byte("Action=DeleteStack"))
	if got != "X.Y Action=DeleteStack" {
		t.Errorf("operation = %q", got)
	}
	if (HTTPHost{}).OperationOf(url.Values{"Action": {"x"}}, nil, nil) != "" {
		t.Error("a host without operation names none")
	}
}

func TestOperationRulesNeedTheirParts(t *testing.T) {
	for _, bad := range []string{
		"[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"*\"\npath = \"/\"\nheader_glob = \"x*\"\naction = \"deny\"\n",
		"[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"*\"\npath = \"/\"\nheader = \"x\"\nheader_prefix = \"a\"\nheader_glob = \"x*\"\naction = \"deny\"\n",
		"[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"*\"\npath = \"/\"\nform = { Action = \"[\" }\naction = \"deny\"\n",
		"[[http]]\nhost = \"a.com\"\noperation = { header = \"bad header\" }\n",
	} {
		if _, err := loader(fstest.MapFS{"p.toml": file(bad)}, fstest.MapFS{}).Load("p"); err == nil {
			t.Errorf("accepted:\n%s", bad)
		} else if !strings.Contains(err.Error(), "header") && !strings.Contains(err.Error(), "form") {
			t.Errorf("unclear error: %v", err)
		}
	}
}
