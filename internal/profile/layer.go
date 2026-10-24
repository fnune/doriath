package profile

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
)

type layer struct {
	Name        string                 `toml:"name"`
	Description string                 `toml:"description"`
	Modules     []string               `toml:"modules"`
	Mounts      []mountLayer           `toml:"mounts"`
	Caches      []cacheLayer           `toml:"caches"`
	Devices     []string               `toml:"devices"`
	Env         envLayer               `toml:"env"`
	Egress      egressLayer            `toml:"egress"`
	HTTP        []httpLayer            `toml:"http"`
	Signing     *signingLayer          `toml:"signing"`
	Podman      *podmanLayer           `toml:"podman"`
	Nix         *nixLayer              `toml:"nix"`
	VCS         *vcsLayer              `toml:"vcs"`
	Clipboard   *clipboardLayer        `toml:"clipboard"`
	MCP         []mcpLayer             `toml:"mcp"`
	Hardening   *hardeningLayer        `toml:"hardening"`
	Limits      *limitsLayer           `toml:"limits"`
	Agent       *agentLayer            `toml:"agent"`
	Claude      *claudeLayer           `toml:"claude"`
	Secrets     map[string]secretLayer `toml:"secrets"`
	source      string
	stateName   string
}

type mountLayer struct {
	Path     string     `toml:"path"`
	Mode     string     `toml:"mode"`
	Optional bool       `toml:"optional"`
	Edit     *editLayer `toml:"edit"`
}

type editLayer struct {
	Format string   `toml:"format"`
	Safe   []string `toml:"safe"`
}

type cacheLayer struct {
	Path string `toml:"path"`
}

type envLayer struct {
	Set         map[string]string `toml:"set"`
	Pass        []string          `toml:"pass"`
	PathPrepend []string          `toml:"path_prepend"`
}

type egressLayer struct {
	Allow    []string        `toml:"allow"`
	Deny     []string        `toml:"deny"`
	Ports    []int           `toml:"ports"`
	TCPPorts []int           `toml:"tcp_ports"`
	Programs []programsLayer `toml:"programs"`
}

type programsLayer struct {
	Binaries []string `toml:"binaries"`
	Allow    []string `toml:"allow"`
}

type httpLayer struct {
	Host           string           `toml:"host"`
	Credential     *credentialLayer `toml:"credential"`
	Default        string           `toml:"default"`
	Repositories   []string         `toml:"repositories"`
	SSH            *sshLayer        `toml:"ssh"`
	EncodedSlashes bool             `toml:"encoded_slashes"`
	Operation      *operationLayer  `toml:"operation"`
	Only           []string         `toml:"only"`
	Rules          []ruleLayer      `toml:"rules"`
}

type operationLayer struct {
	Header string `toml:"header"`
	Form   string `toml:"form"`
}

type sshLayer struct {
	User  string   `toml:"user"`
	Port  int      `toml:"port"`
	Hosts []string `toml:"hosts"`
}

type credentialLayer struct {
	Secret   string   `toml:"secret"`
	Scheme   string   `toml:"scheme"`
	Username string   `toml:"username"`
	Header   string   `toml:"header"`
	KeyID    string   `toml:"key_id"`
	Binaries []string `toml:"binaries"`
}

type ruleLayer struct {
	Method       string            `toml:"method"`
	Path         string            `toml:"path"`
	BodyContains []string          `toml:"body_contains"`
	GraphQL      *graphQLLayer     `toml:"graphql"`
	Header       string            `toml:"header"`
	HeaderPrefix string            `toml:"header_prefix"`
	HeaderGlob   string            `toml:"header_glob"`
	Form         map[string]string `toml:"form"`
	MCPTools     []string          `toml:"mcp_tools"`
	MCPNone      bool              `toml:"-"`
	Action       string            `toml:"action"`
	Summary      string            `toml:"summary"`
	Credential   *credentialLayer  `toml:"credential"`
}

type graphQLLayer struct {
	Operation string    `toml:"operation"`
	Fields    *[]string `toml:"fields"`
}

type signingLayer struct {
	Key    string `toml:"key"`
	Enable *bool  `toml:"enable"`
}

type limitsLayer struct {
	Tasks  *int   `toml:"tasks"`
	Memory string `toml:"memory"`
	CPU    string `toml:"cpu"`
}

type hardeningLayer struct {
	Namespaces *bool `toml:"namespaces"`
	Ptrace     *bool `toml:"ptrace"`
	Landlock   *bool `toml:"landlock"`
}

type nixLayer struct {
	Daemon *bool `toml:"daemon"`
}

type mcpLayer struct {
	Name    string            `toml:"name"`
	Command []string          `toml:"command"`
	Env     map[string]string `toml:"env"`
	URL     string            `toml:"url"`
	Secret  string            `toml:"secret"`
	Default string            `toml:"default"`
	Allow   []string          `toml:"allow"`
	Approve []string          `toml:"approve"`
	Deny    []string          `toml:"deny"`
}

type vcsLayer struct {
	Store *bool `toml:"store"`
}

type clipboardLayer struct {
	Images *bool `toml:"images"`
}

type podmanLayer struct {
	Enabled *bool    `toml:"enabled"`
	Images  []string `toml:"images"`
}

type agentLayer struct {
	StatusLine      *bool    `toml:"statusline"`
	ApprovalTimeout string   `toml:"approval_timeout"`
	Instructions    []string `toml:"instructions"`
}

type claudeLayer struct {
	DisableConnectors *bool    `toml:"disable_connectors"`
	DeniedMCPServers  []string `toml:"denied_mcp_servers"`
	Ask               []string `toml:"ask"`
	Deny              []string `toml:"deny"`
}

func decodeLayer(origin string, data []byte) (layer, error) {
	var l layer
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&l)
	if err != nil {
		return layer{}, fmt.Errorf("%s: %w", origin, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return layer{}, fmt.Errorf("%s: unknown keys: %s", origin, strings.Join(keys, ", "))
	}

	for _, key := range md.Keys() {
		for i, part := range key {
			if i > 0 && key[i-1] == "form" {
				continue
			}
			if part != strings.ToLower(part) && fieldNames[strings.ToLower(part)] {
				return layer{}, fmt.Errorf("%s: key %q: write it in lower case", origin, key.String())
			}
		}
	}
	return l, nil
}

var fieldNames = tomlFieldNames(reflect.TypeOf(layer{}), map[string]bool{})

func tomlFieldNames(t reflect.Type, names map[string]bool) map[string]bool {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map:
		return tomlFieldNames(t.Elem(), names)
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if name, _, _ := strings.Cut(f.Tag.Get("toml"), ","); name != "" && name != "-" {
				names[name] = true
			}
			tomlFieldNames(f.Type, names)
		}
	}
	return names
}

type secretLayer struct {
	File    string      `toml:"file"`
	Command []string    `toml:"command"`
	OAuth   *oauthLayer `toml:"oauth"`
	Refresh string      `toml:"refresh"`
}

type oauthLayer struct {
	MCP      string   `toml:"mcp"`
	Issuer   string   `toml:"issuer"`
	ClientID string   `toml:"client_id"`
	Scopes   []string `toml:"scopes"`
}
