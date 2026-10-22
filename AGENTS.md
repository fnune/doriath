# Notes for agents

- Read [docs/engineering.md](docs/engineering.md) before changing code: it sets the principles, the layering, the testing seams and the commit conventions.
- Write prose in Simplified Technical English (ASD-STE100), in a pragmatic form. Put the conclusion first and conditions before instructions. Keep sentences short, at most 20 words for an instruction and 25 for a description. Use active voice, simple tenses and one word for each concept. Do not use phrasal verbs, idioms, contractions or semicolons. Technical terms, commands and identifiers stay exact. [site/STYLE.md](site/STYLE.md) has the full list.
- Prose you write, in docs, the site, comments, commit messages and error messages, follows [site/STYLE.md](site/STYLE.md). Its list of patterns that read as generated applies everywhere: no sentences in matching pairs or triplets, no "not X, but Y", no question headings, and none of the listed words.
- Keep generic code free of agent and forge names. An agent's specifics live in its module, and in its adapter under `internal/agents/` only where data cannot express them. A forge's specifics live in its module, as `[[http]]` entries and rules. Choose behaviour from the profile's modules, never from a command name or a host name in Go.
- Before you add a case for Claude Code or GitHub, check how a second agent (Codex, Gemini CLI) or a second forge (GitLab, Forgejo) would need the same thing, and build the general mechanism.
- In docs, describe a generic feature in neutral words, and name Claude Code or GitHub only as an example. Detail that applies to one agent or one forge goes on its own page.
- The approvals page and the documentation site share their look through `internal/ui`. Change it there, and check both.
- User documentation lives in `site/src/content/docs` and is published at https://doriath.fnune.com. Link there from Markdown in the repository instead of repeating it. `docs/` holds only what contributors need.
- [site/STYLE.md](site/STYLE.md) also sets how pages are structured: cross-link keys, modules and commands to their reference, introduce examples, explain outside tools before using them, cover remote hosts, and give real reasons instead of labels. Apply the same habits to READMEs and to Markdown elsewhere in the repository.
- Docs describe doriath as it is meant to work. Track where the code falls short in the todo list, and remove an item when a change closes it.
- When a change opens or closes a gap, update the security limits page with it. Escape scripts marked `expect: gap` fail until it matches.
- Examples in TOML code blocks on the site must load: `TestDocExamplesLoad` checks each one.
