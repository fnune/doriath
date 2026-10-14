package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
)

const localHeader = "# Written by girdle when you approve a drafted rule. Edit or delete as you like.\n\n"

// AddEgressHost appends a host to the profile's local layer in dir.
func AddEgressHost(dir, profile, host string) error {
	if _, err := ParseHostPattern(host); err != nil {
		return err
	}
	return editLocal(dir, profile, func(doc map[string]any) bool {
		egress, _ := doc["egress"].(map[string]any)
		if egress == nil {
			egress = map[string]any{}
		}
		var allow []string
		if list, ok := egress["allow"].([]any); ok {
			for _, h := range list {
				if s, ok := h.(string); ok {
					allow = append(allow, s)
				}
			}
		}
		if slices.Contains(allow, host) {
			return false
		}
		egress["allow"] = append(allow, host)
		doc["egress"] = egress
		return true
	})
}

func editLocal(dir, profile string, change func(doc map[string]any) bool) error {
	path := filepath.Join(dir, LocalFile(profile))
	doc := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read %s: %w", path, err)
	default:
		if _, err := toml.Decode(string(data), &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	if !change(doc) {
		return nil
	}
	var buf bytes.Buffer
	buf.WriteString(localHeader)
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}
