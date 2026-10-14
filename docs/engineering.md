# Engineering principles

Principles and conventions for this repository. Adapted from the [openmusa engineering principles](https://github.com/openmusa/openmusa/blob/main/engineering/README.md) for a Go CLI that sandboxes coding agents.

---

## Principles

### Calm tool

Girdle sits between a person and their agents. It must feel calm: simple, clear, predictable, respectful of the person's attention. Engineers carry this through to the code, the CLI output, the defaults, and the failure paths.

- Simplicity is the default. A feature earns its place or it does not ship.
- Clarity over cleverness. Plain output, ordinary words, predictable defaults.
- Quiet by default. A successful command prints nothing it does not need to. Detail lives in the audit log.
- Respect the person's agency. They decide what an agent can reach. Girdle never widens access on its own and never hides what it granted.
- Failures are shown calmly. Error messages are accurate and plain, say what was blocked and how to allow it, and never blame the person.
- An approval request earns the interruption or it does not happen. Routine grants last for a session. Only rare, sensitive actions ask each time.

### Secure by default

- Deny by default. A host, socket, credential, environment variable or path under the home is in the jail only if a profile names it. The system directories (`/etc`, `/usr`, `/var`, `/opt`, `/nix/store`) stay readable so that tools work, and nothing outside the writable paths can be changed.
- Hide rather than deny. What the agent must not reach is not mounted, not forwarded, and not in its environment.
- Widen only by the person's decision. An agent can ask for a host or a writable path, and the person allows it for the session. Only the person edits a profile; girdle prints the lines and never writes them.
- Secrets never enter logs, errors, test fixtures, or the agent's environment unless a profile grants them. Redact at the boundary that writes output.
- Every grant and every denial goes to the audit log.

### Testability via dependency injection

Reference: [Mark Seemann](https://blog.ploeh.dk/), [_Dependency Injection Principles, Practices, and Patterns_](https://www.manning.com/books/dependency-injection-principles-practices-patterns).

- Constructor injection is the default: `NewManager(clock Clock, notifier Notifier, recorder Recorder, ids IDs) *Manager`. Functional options only when a constructor has many optional settings.
- Inject volatile dependencies: anything with side effects (process execution, file system, sockets, network, D-Bus), nondeterminism (time, randomness), or runtime configuration.
- Do not inject stable dependencies: the standard library's pure functions, value types, and deterministic helpers.
- The composition root is `cmd/girdle/main.go`. It is the only place that knows the concrete implementations of volatile dependencies.
- Pure DI: hand-wired object graphs. No DI container, no `init()` registration, no package-level mutable state.
- No service locator and no ambient context. Do not reach for `time.Now()`, `os.Getenv` or `os.Exec` from domain code. Receive a `Clock`, the config, or a `Runner` instead.
- A growing constructor argument list is a sign that a type does too much.
- Tests follow the seams DI creates. Hand-written in-memory fakes for volatile dependencies, no mocking frameworks. Integration tests run the real jail (bubblewrap, sockets, proxy) where the machine supports it.
- Every way out of the jail that girdle closes has a script in `internal/session/testdata/escapes`, run in a real jail by `TestEscapes`. A script names its threat and exits 0 when the guard held. A new finding becomes a new script. Scripts marked `expect: gap` document a limit from [security limits](security-limits.md) and fail once the gap closes, so the docs change with the code.

### Layered architecture and abstraction ownership

- Packages live under `internal/`. The domain (`profile`, `approval`) holds the rules and declares the interfaces it needs.
- Adapters (`jail`, `proxy`, `containers`, `promote`, `vcs`, `sshagent`, `notify`, `agents/claude`) import the domain and implement its interfaces. The domain never imports an adapter.
- The interface belongs to the consumer, not to the implementer. Accept interfaces, return concrete types.
- Reject naive layering where each package depends on the one below it. That is not dependency inversion.

### Supporting agents

- An agent is a module first: its config, state, provider hosts and credentials are mounts, caches, `[egress]` and `[[http]]` entries, as for any tool.
- girdle teaches every agent the same way: the `girdle status` text, built from the live session, and errors that say what was blocked and what to run. The text goes where the agent reads instructions, never into the repository's AGENTS.md.
- A Go adapter under `internal/agents/` exists only for what data cannot express, so that a supported agent behaves well: its permission prompts reach girdle's approval queue, and its transcripts come back to your own config when the session ends.
- An agent without an adapter still works in a jail with a one-line instruction: "When something is blocked, run `girdle status`."

### Strict typing and validated boundaries

- No `any` or `interface{}` in domain code. Use them only at a decoding boundary, and convert to concrete types at once.
- Validate at every process boundary: profile TOML, socket requests, hook payloads, environment variables, agent output. Decode strictly (unknown fields are errors), then validate, then build domain values. Never trust a value because it type-checks.
- Use distinct types for distinct concepts, such as `HostPattern`, `PathPattern` and `Mode`, not bare strings.
- `golangci-lint` runs with a shared config. A `//nolint` without a reason on the same line is a bug.

### Code comments

- Code is self-evident. Comments are a last resort.
- A comment is only justified by a non-obvious why: a kernel constraint, a bubblewrap argument-ordering rule, a workaround for a specific upstream bug.
- Comments that restate what the code does are noise.

### Dependency hygiene

- Start with the standard library: `net/http`, `net`, `log/slog`, `encoding/json`, `flag`, `os/exec`, `testing`, `crypto/*`.
- Vet every dependency: can the standard library do it, the size of its transitive tree, active maintenance, license compatibility with MIT and with redistribution in a single binary.
- Prefer governance-neutral dependencies over open source that exists to feed a vendor's hosted product. Use such a dependency only when no neutral alternative exists, and document the choice in the PR.
- If it is under 50 lines, write it. Do not depend.
- Vendor utilities under 100 lines with attribution and the original license.
- Budget: under 10 direct Go module dependencies. Exceeding requires written justification in the PR.
- Commit `go.mod` and `go.sum`. Treat changes to them as code changes.
- Few system dependencies. Runtime requirements are kernel features and services the OS provides. Helpers such as `bwrap` are bundled as static binaries, pinned by version and SHA-256, built reproducibly with nix, and shipped with their licenses and source references.

### Operational discipline

- Error handling. No ignored errors. Wrap with context using `fmt.Errorf("start proxy for profile %q: %w", name, err)`. Distinguish errors the person can fix (a missing profile entry) from bugs. The CLI boundary decides what to show. Deeper layers return errors and trust the boundary.
- Observability. Structured logs with `log/slog`. The audit log is JSON Lines, one record per grant, denial and approval, with the session and profile on every record.
- Security baseline. Least privilege on every credential. Secrets never in code, never in committed files, never in logs.
- Privacy. Girdle has no telemetry and makes no network calls of its own. Transcripts, tokens and audit logs stay on the machine.

### Local checks before pushing

- Run cheap checks locally: `just fmt`, `just lint`, and the tests that cover the change.
- `just check` runs format check, lint, `go vet` and the unit tests. `just test-integration` runs the tests that start a real jail.
- Parsers and decisions that see agent-controlled input have fuzz tests that check a security property. Their seeds run with the unit tests. `just fuzz` searches for new inputs, 30 seconds per target by default (`just fuzz 5m` for longer).
- `just mutate` runs mutation testing with [gremlins](https://github.com/go-gremlins/gremlins) over the security-critical packages. It is slow, so it runs now and then by hand, not in CI. A mutant that survives in a guard means no unit test checks that guard.

### Git conventions

- [Conventional Commits](https://www.conventionalcommits.org/) for every commit message. Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `revert`. Scope optional and lowercase, for example `feat(broker):`, `fix(jail):`.
- Imperative mood. "Add the X", not "Added the X".
- Subject line under 72 characters. Body wraps at 80.
- The body explains why when the why is not obvious from the diff. Reference the issue or the decision record.
- No value-judgement words: "improve", "better", "cleaner", "robust", "elegant". State the change in concrete terms.
- No vague qualifiers: "various", "several minor", "ensure", "make sure".
- No AI attribution and no Co-Authored-By for AI tools.
- One commit per PR is the default. Squash on merge. Split larger changes at natural seams.

### Continuous integration

- Every PR runs the same baseline as `just check`, plus the integration tests and `govulncheck`. Same commands locally and in CI.
- One workflow at `.github/workflows/ci.yml`.

### Reproducible, one-command developer environments

- The same Go version, linters and bundled helper versions on every machine and in CI.
- One command to set up: `nix develop`, or `direnv allow` with the repo's `.envrc`.
- The flake is the single source of truth. It also builds the static helpers that the binary bundles, so their versions are pinned in `flake.lock`.

### Toolchain choices

- Go for the CLI and all helpers. One static binary per architecture, no runtime to install, a standard library that covers sockets, HTTP proxying and process control.
- Linux first. macOS backends come later, behind the same interfaces.
- [gofumpt](https://github.com/mvdan/gofumpt) for formatting, [golangci-lint](https://golangci-lint.run/) for linting, the standard `testing` package for tests.
- [just](https://just.systems/) for task recipes, the same recipe names locally and in CI.
- Dependency updates via [Renovate](https://docs.renovatebot.com/). Weekly batch, 7 day minimum release age, no auto-merge. Security advisories handled the same day.

### Writing style

- Sentence case in headings.
- Bold sparingly.
- No em-dashes. Use a colon, comma, semicolon, period, or rephrase.
- No rhetorical triplets.
- No AI attribution in commit messages or code.

---

## Use of AI and LLMs

This project accepts the use of LLMs to write code. The tools used to build software are changing quickly, but this code is held to the same standards as code written without LLMs.

- Tests at the unit, integration, and end-to-end levels.
- Strict typing and validated boundaries.
- Dependency hygiene and supply-chain discipline as set out above.
- Architecture and code review applied to every change, AI-assisted or not.
