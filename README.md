# Doriath

Doriath runs a coding agent such as Claude Code in a jail on your Linux machine, and sends every request it makes through a proxy that follows the rules of a profile you write. Tokens stay in the proxy, and merges, pushes and unknown hosts wait for your answer.

Pre-alpha, Linux only. The documentation lives at [doriath.fnune.com](https://doriath.fnune.com).

```sh
nix profile install github:fnune/doriath
doriath doctor
cd ~/Development/my-app
doriath run --profile my-app -- claude
```

- [Install](https://doriath.fnune.com/install/) walks from nothing to a first session, profile and credentials included.
- [Architecture](https://doriath.fnune.com/architecture/) covers the jail, the proxy, approvals and repositories.
- [Threat model](https://doriath.fnune.com/threat-model/) and [security limits](https://doriath.fnune.com/reference/security-limits/) say what doriath guards against and what it leaves open.
- [Configuration](https://doriath.fnune.com/reference/configuration/) lists every key.

## Development

`nix develop` provides the toolchain. `just check` runs formatting, lint and the unit tests, and `just test-integration` the tests that start real jails. [docs/engineering.md](docs/engineering.md) sets how the code is written, and [AGENTS.md](AGENTS.md) adds notes for coding agents. The documentation site is in [site/](site/), with `just site-dev` to preview it.
