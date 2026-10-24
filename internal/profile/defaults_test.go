package profile

import (
	"slices"
	"testing"
	"testing/fstest"
)

func TestAProfileWithoutModulesPassesTheTerminalAndLocale(t *testing.T) {
	p, err := loader(fstest.MapFS{"bare.toml": file("")}, fstest.MapFS{}).Load("bare")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"PATH", "TERM", "LANG"} {
		if !slices.Contains(p.Env.Pass, name) {
			t.Errorf("env pass lacks %s: %v", name, p.Env.Pass)
		}
	}
	if len(p.Modules) != 0 {
		t.Errorf("the defaults show as a module: %v", p.Modules)
	}
}

func TestAWSToolsDoNotWaitOnAMetadataServiceTheJailCannotReach(t *testing.T) {
	p, err := loader(fstest.MapFS{"bare.toml": file("")}, fstest.MapFS{}).Load("bare")
	if err != nil {
		t.Fatal(err)
	}
	if p.Env.Set["AWS_EC2_METADATA_DISABLED"] != "true" {
		t.Errorf("env set = %v", p.Env.Set)
	}
}

func TestAProfileCanOverrideADefaultVariable(t *testing.T) {
	p, err := loader(fstest.MapFS{"aws.toml": file("[env]\nset = { AWS_EC2_METADATA_DISABLED = \"false\" }\n")}, fstest.MapFS{}).Load("aws")
	if err != nil {
		t.Fatal(err)
	}
	if p.Env.Set["AWS_EC2_METADATA_DISABLED"] != "false" {
		t.Errorf("env set = %v", p.Env.Set)
	}
}
