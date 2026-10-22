# Notes for agents

- Read [docs/engineering.md](docs/engineering.md) before changing code: it sets the principles, the layering, the testing seams and the commit conventions.
- Prose you write, in docs, the site, comments, commit messages and error messages, follows [site/STYLE.md](site/STYLE.md). Its list of patterns that read as generated applies everywhere: no sentences in matching pairs or triplets, no "not X, but Y", no question headings, and none of the listed words.
- The approvals page and the documentation site share their look through `internal/ui`. Change it there, and check both.
- Pages in `site/` that repeat a file in `docs/` change together with it.
