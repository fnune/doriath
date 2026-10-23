// Package guide holds the steps that doriath prints for an agent that sets
// up a profile, and the skill that points the agent at them.
package guide

import _ "embed"

//go:embed profile.md
var Profile string

//go:embed setting-up-doriath-profiles/SKILL.md
var Skill string
