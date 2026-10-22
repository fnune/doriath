# Documentation style guide

Rules for the pages in `src/content/docs`, and for any prose an agent writes in this repository.

## Prose

- Sentence case in headings.
- No bold, no em-dashes, no emoji.
- Second person ("you"), present tense ("doriath refuses"), imperative mood for instructions ("run the command").
- Prefer short paragraphs to bullets. Bullets are for lists of items, not for explaining how something works.
- No value judgements and no comparisons that rank doriath. State what it does and what it leaves open.
- Backticks for commands, paths, config keys, module names and code.
- Say what a limit is when a page describes a protection. Link to the security limits page for the full list.

## Patterns that read as generated

Rewrite any of these on sight:

- Two or three sentences in a row with the same structure, such as "The agent sees X. The agent reaches Y. The agent gets Z." Vary the subject, the length and the order, or merge them.
- Lists of exactly three adjectives, benefits or clauses, used for rhythm rather than because there are three things.
- Negative parallelism: "not X, but Y", "X isn't just Y, it's Z", "no X, no Y".
- Headings phrased as questions or starting with a question word: "What it is", "How it works", "Why it matters". Name the subject instead: "Architecture", "Threat model".
- Rhetorical questions, and a colon that sets up a reveal ("The result: ...", "Here's the thing: ...").
- A closing sentence that restates the section ("In short", "In summary", "Ultimately").
- Openers that announce instead of saying: "It's worth noting", "Keep in mind", "Note that", "Importantly".
- "Whether you're X or Y", and "from X to Y" used to sound broad.

Words to avoid, with what to say instead:

| Avoid                                                       | Write                                    |
| ----------------------------------------------------------- | ---------------------------------------- |
| delve, dive into, explore (a topic)                         | describe, explain, or nothing            |
| robust, powerful, seamless, comprehensive, cutting-edge     | the property itself: "refuses", "checks" |
| crucial, vital, essential, key, pivotal                     | nothing, or "needed" when it is          |
| leverage, utilize, harness, empower, unlock, elevate        | use, let                                 |
| streamline, navigate, foster, bolster, showcase, underscore | the concrete verb                        |
| ensures, serves as, stands as, boasts, a testament to       | is, has, does                            |
| simple, easy, just, simply, effortless, out of the box      | nothing                                  |
| landscape, realm, ecosystem, journey, tapestry              | the actual thing                         |
| notably, ultimately, effectively, essentially               | nothing                                  |

## Structure

- Every page has a frontmatter `title` and `description`.
- Code blocks have a language tag.
- Config examples show only the keys that matter, not a whole file.
- Use Starlight's `<Aside>` for notes and cautions.
- Describe planned features as planned, never as if they exist.
- Pages that repeat a file in `docs/` change together with it.

## Look

The site uses the tokens, components, ornaments and fonts of the approvals page from `internal/ui`. Use them instead of new colors or shapes: `RequestExample` shows a request as the page does, `Flourish` divides sections, and `Ornament` draws the mark and the curls.
