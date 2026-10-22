# Documentation style guide

Rules for the pages in `src/content/docs`.

## Prose

- Sentence case in headings.
- No bold, no em-dashes, no emoji.
- Second person ("you"), present tense ("doriath refuses"), imperative mood for instructions ("run the command").
- Prefer short paragraphs to bullets. Bullets are for lists of items, not for explaining how something works.
- No value judgements and no comparisons that rank doriath. State what it does and what it leaves open.
- No marketing words such as "simple", "easy", "seamless" or "just works".
- Backticks for commands, paths, config keys, module names and code.
- Say what a limit is when a page describes a protection. Link to the security limits page for the full list.

## Structure

- Every page has a frontmatter `title` and `description`.
- Code blocks have a language tag.
- Config examples show only the keys that matter, not a whole file.
- Use Starlight's `<Aside>` for notes and cautions.
- Describe planned features as planned, never as if they exist.
- Pages that repeat a file in `docs/` change together with it.

## Look

The site uses the tokens, components, ornaments and fonts of the approvals page from `internal/ui`. Use them instead of new colors or shapes: `RequestExample` shows a request as the page does, `Flourish` divides sections, and `Ornament` draws the mark and the curls.
