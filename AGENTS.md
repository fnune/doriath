# Notes for agents

- Read [docs/engineering.md](docs/engineering.md) before changing code: it sets the principles, the layering, the testing seams and the commit conventions.
- Prose you write, in docs, the site, comments, commit messages and error messages, follows [site/STYLE.md](site/STYLE.md). Its list of patterns that read as generated applies everywhere: no sentences in matching pairs or triplets, no "not X, but Y", no question headings, and none of the listed words.
- The approvals page and the documentation site share their look through `internal/ui`. Change it there, and check both.
- User documentation lives in `site/src/content/docs` and is published at https://doriath.fnune.com. Link there from Markdown in the repository instead of repeating it. `docs/` holds only what contributors need.
- When a change opens or closes a gap, update the security limits page with it. Escape scripts marked `expect: gap` fail until it matches.
- Examples in TOML code blocks on the site must load: `TestDocExamplesLoad` checks each one.
