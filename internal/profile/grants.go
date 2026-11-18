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

func (p *Profile) Grants() ([]string, error) {
	return p.grantsWithout(nil)
}

func (p *Profile) OnlyAddsDenyRules(approved []string) (bool, error) {
	now, err := p.Grants()
	if err != nil {
		return false, err
	}
	added := map[string]bool{}
	for _, line := range Added(approved, now) {
		if strings.Contains(line, OrderSuffix) {
			continue
		}
		if !strings.Contains(line, `"Action":"deny"`) {
			return false, nil
		}
		added[line] = true
	}
	if len(added) == 0 || len(Removed(approved, now)) > 0 {
		return false, nil
	}
	without, err := p.grantsWithout(added)
	if err != nil {
		return false, err
	}
	return len(Added(approved, without)) == 0 && len(Removed(approved, without)) == 0, nil
}

func (p *Profile) grantsWithout(skip map[string]bool) ([]string, error) {
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
	w := grantWriter{skip: skip}
	w.flatten("", top)
	lines := w.lines
	slices.Sort(lines)
	return slices.Compact(lines), nil
}

type grantWriter struct {
	lines []string
	skip  map[string]bool
}

func (w *grantWriter) flatten(prefix string, v any) {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			w.flatten(join(prefix, k), child)
		}
	case []any:
		w.flattenList(prefix, v)
	case nil:
	case string:
		if v != "" {
			w.lines = append(w.lines, prefix+": "+v)
		}
	default:
		data, _ := json.Marshal(v)
		w.lines = append(w.lines, prefix+": "+string(data))
	}
}

func (w *grantWriter) flattenList(prefix string, list []any) {
	var order []string
	for _, child := range list {
		obj, ok := child.(map[string]any)
		if !ok {
			data, _ := json.Marshal(child)
			order = append(order, string(data))
			w.flatten(prefix, child)
			continue
		}
		if key, ok := nameKey(obj); ok {
			name := obj[key].(string)
			delete(obj, key)
			order = append(order, name)
			w.lines = append(w.lines, prefix+"["+name+"]")
			w.flatten(prefix+"["+name+"]", obj)
			continue
		}
		data, _ := json.Marshal(withoutZeros(obj))
		line := prefix + ": " + string(data)
		if w.skip[line] {
			continue
		}
		order = append(order, string(data))
		w.lines = append(w.lines, line)
	}
	if len(order) > 1 && !slices.Contains(unordered, prefix) {
		sum := sha256.Sum256([]byte(strings.Join(order, "\n")))
		w.lines = append(w.lines, prefix+OrderSuffix+hex.EncodeToString(sum[:4]))
	}
}

var unordered = []string{"Mounts"}

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
