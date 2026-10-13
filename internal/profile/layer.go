package profile

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// layer is one TOML document: a module or a profile. Pointer fields tell
// "not set" apart from the zero value, so later layers only override what
// they name.
type layer struct {
	Name        string            `toml:"name"`
	Description string            `toml:"description"`
	Modules     []string          `toml:"modules"`
	Match       []string          `toml:"match"`
	Mounts      []mountLayer      `toml:"mounts"`
	Caches      []cacheLayer      `toml:"caches"`
	Devices     []string          `toml:"devices"`
	Env         envLayer          `toml:"env"`
	Egress      egressLayer       `toml:"egress"`
	HTTP        []httpLayer       `toml:"http"`
	Signing     *signingLayer     `toml:"signing"`
	Podman      *podmanLayer      `toml:"podman"`
	Claude      *claudeLayer      `toml:"claude"`
	Secrets     map[string]string `toml:"secrets"`
}

type mountLayer struct {
	Path     string `toml:"path"`
	Mode     string `toml:"mode"`
	Optional bool   `toml:"optional"`
}

type cacheLayer struct {
	Path string `toml:"path"`
}

type envLayer struct {
	Set  map[string]string `toml:"set"`
	Pass []string          `toml:"pass"`
}

type egressLayer struct {
	Allow []string `toml:"allow"`
	Ports []int    `toml:"ports"`
}

type httpLayer struct {
	Host       string           `toml:"host"`
	Credential *credentialLayer `toml:"credential"`
	Default    string           `toml:"default"`
	Rules      []ruleLayer      `toml:"rules"`
}

type credentialLayer struct {
	Secret   string `toml:"secret"`
	Scheme   string `toml:"scheme"`
	Username string `toml:"username"`
}

type ruleLayer struct {
	Method       string   `toml:"method"`
	Path         string   `toml:"path"`
	BodyContains []string `toml:"body_contains"`
	Action       string   `toml:"action"`
	Summary      string   `toml:"summary"`
}

type signingLayer struct {
	Key string `toml:"key"`
}

type podmanLayer struct {
	Enabled *bool `toml:"enabled"`
}

type claudeLayer struct {
	DisableConnectors *bool    `toml:"disable_connectors"`
	DeniedMCPServers  []string `toml:"denied_mcp_servers"`
	Ask               []string `toml:"ask"`
	Deny              []string `toml:"deny"`
	ApprovalTimeout   string   `toml:"approval_timeout"`
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
	return l, nil
}
