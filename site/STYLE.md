# Documentation style guide

Rules for the pages in `src/content/docs`, and for any prose an agent writes in this repository.

## Prose

Write in Simplified Technical English, after ASD-STE100, in a pragmatic form: the rules apply to the prose, and the domain words of doriath, Linux and git stay as they are.

- Put the conclusion or the instruction first. Reasons and caveats come after it.
- Put a condition before its instruction: "If the check fails, run `doriath doctor`."
- Keep instructions to 20 words or fewer, with one instruction in each sentence. Keep descriptions to 25 words or fewer, with one topic in each paragraph.
- Use active voice and simple tenses: the simple present, past and future, the imperative and the infinitive. Do not use perfect or progressive tenses.
- Use only the modals "can", "will" and "must".
- Use one word for one concept, and do not change the word for variety.
- Do not use noun clusters of more than three words. Use prepositions to break them up.
- Do not use phrasal verbs, idioms, contractions or semicolons.
- Keep the articles, the pronouns and "that". The text is plain prose, not a telegram.
- Keep commands, flags, paths, error text and numbers exactly as they are.

- Sentence case in headings.
- No bold, no em-dashes, no emoji.
- Second person ("you"), present tense ("doriath refuses"), imperative mood for instructions ("run the command").
- Keep each paragraph to four lines or fewer on a desktop screen: about 70 words, or three to four sentences. Split a longer paragraph by topic, or turn a list of facts into a list.
- Cut what the reader does not need to act: background, history and repeated caveats. Link to the page that has the detail.
- Prefer short paragraphs to bullets. Bullets are for lists of items, not for explaining how something works.
- No value judgements and no comparisons that rank doriath. State what it does and what it leaves open. A comparison with other tools states the facts of each tool, with sources, and leaves the conclusion to the reader.
- Backticks for commands, paths, config keys, module names and code.
- Say what a limit is when a page describes a protection. Link to the limits on the threat model page for the full list.

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
- Describe doriath as it is meant to work, with no "yet", "so far", "known issues" or release status. Where the code falls short, the gap goes in the project's TODO list outside the repository, not on a page.
- The limits on the threat model page are the exception: a protection the code does not provide stays listed there as a limit until it does.
- Each topic has one page. Link to it instead of repeating it on another.
- Link a config key, module, command or concept to its reference the first time a page names it.
- Where a page describes behaviour a setting controls, link to where it is set.
- Introduce every example and illustration: say what it shows, and how to open the real thing.
- Open a page about an outside tool, such as home-manager or direnv, with a paragraph on what the tool does, and say who can skip the page.
- Where behaviour depends on a desktop session or the local machine, say how it works on a remote or headless host.
- Do not put long code, such as command usage, in table cells, where it wraps badly. Give each item a heading, its code on its own line, and its description under it.
- Show alternatives, such as ways to install, as tabs, leading with the one that needs nothing beyond the operating system.
- Say which names doriath or a module fixes and which the reader chooses.
- Give the real reason for an option instead of a label that assumes the reader's setup, such as calling one kind of configuration public and another private.

## Look

The site uses the tokens, components, ornaments and fonts of the approvals page from `internal/ui`. Use them instead of new colors or shapes: `RequestExample` shows a request as the page does, `Flourish` divides sections, and `Ornament` draws the mark and the curls.
