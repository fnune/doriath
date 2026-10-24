package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

var notGrants = []string{"Name", "Description", "Modules", "Sources", "SecretOwners", "PathRules"}

// Grants lists what the profile gives the jail, one line per setting, so
// that two versions of a profile compare line by line. An entry of a list
// is named by its host, name or path where it has one. Other entries, such
// as rules, are one line each. One more line holds the order of each list.
func (p *Profile) Grants() ([]string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("list the grants of profile %s: %w", p.Name, err)
	}
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("list the grants of profile %s: %w", p.Name, err)
	}
	for _, k := range notGrants {
		delete(top, k)
	}
	if egress, ok := top["Egress"].(map[string]any); ok {
		delete(egress, "Notes")
		delete(egress, "Deny")
	}
	var lines []string
	flatten("", top, &lines)
	slices.Sort(lines)
	return slices.Compact(lines), nil
}

func flatten(prefix string, v any, lines *[]string) {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			flatten(join(prefix, k), child, lines)
		}
	case []any:
		flattenList(prefix, v, lines)
	case nil:
	case string:
		if v != "" {
			*lines = append(*lines, prefix+": "+v)
		}
	default:
		data, _ := json.Marshal(v)
		*lines = append(*lines, prefix+": "+string(data))
	}
}

func flattenList(prefix string, list []any, lines *[]string) {
	var order []string
	for _, child := range list {
		obj, ok := child.(map[string]any)
		if !ok {
			data, _ := json.Marshal(child)
			order = append(order, string(data))
			flatten(prefix, child, lines)
			continue
		}
		if key, ok := nameKey(obj); ok {
			name := obj[key].(string)
			delete(obj, key)
			order = append(order, name)
			*lines = append(*lines, prefix+"["+name+"]")
			flatten(prefix+"["+name+"]", obj, lines)
			continue
		}
		data, _ := json.Marshal(withoutZeros(obj))
		order = append(order, string(data))
		*lines = append(*lines, prefix+": "+string(data))
	}
	if len(order) > 1 && !slices.Contains(unordered, prefix) {
		sum := sha256.Sum256([]byte(strings.Join(order, "\n")))
		*lines = append(*lines, prefix+OrderSuffix+hex.EncodeToString(sum[:4]))
	}
}

var unordered = []string{"Mounts"}

// OrderSuffix marks the grant that changes when the entries of a list
// change order, such as the arguments of a command, or rules where the
// first that matches wins.
const OrderSuffix = " in order "

func nameKey(obj map[string]any) (string, bool) {
	if _, rule := obj["Action"]; rule {
		return "", false
	}
	for _, k := range []string{"Host", "Name", "Path"} {
		if s, ok := obj[k].(string); ok && s != "" {
			return k, true
		}
	}
	return "", false
}

func withoutZeros(obj map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		switch v := v.(type) {
		case nil:
			continue
		case bool:
			if !v {
				continue
			}
		case string:
			if v == "" {
				continue
			}
		case []any:
			if len(v) == 0 {
				continue
			}
		case map[string]any:
			if len(v) == 0 {
				continue
			}
		}
		out[k] = v
	}
	return out
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// Added returns the grants in now that approved does not have: what a
// profile gives the jail beyond what you last allowed.
func Added(approved, now []string) []string {
	var out []string
	for _, g := range now {
		if _, found := slices.BinarySearch(approved, g); !found {
			out = append(out, g)
		}
	}
	return out
}

// Removed returns the grants in approved that now lacks and that held the
// jail back: a deny or approve rule, a hidden path, the programs or hosts
// a credential is limited to, a host default, or an agent's own refusals.
// Without them the profile gives more, although no line was added.
func Removed(approved, now []string) []string {
	var out []string
	for _, g := range approved {
		if _, found := slices.BinarySearch(now, g); !found && Restrictive(g) {
			out = append(out, g)
		}
	}
	return out
}

var restrictiveSuffixes = []string{".Mode: hide", `"Action":"deny"`, `"Action":"approve"`, ".Default: deny", ".Default: approve"}

var restrictiveKeys = []string{".Credential.Binaries: ", ".Only: ", "Claude.Deny: ", "Claude.Ask: ", "Claude.DeniedMCPServers: ", "Claude.AllowedMCPServers: ", "Limits."}

// Restrictive says whether a grant line limits what the jail can do, so
// that dropping it widens the profile.
func Restrictive(line string) bool {
	if strings.Contains(line, OrderSuffix) {
		return false
	}
	for _, s := range restrictiveSuffixes {
		if strings.Contains(line, s) {
			return true
		}
	}
	for _, k := range restrictiveKeys {
		if strings.Contains(line, k) {
			return true
		}
	}
	return false
}
