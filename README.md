# Doriath

Doriath runs a coding agent such as Claude Code in a jail on your Linux machine, and sends every request it makes through a proxy that follows the rules of a profile you write. Tokens stay in the proxy, and merges, pushes and unknown hosts wait for your answer.

I build doriath because I want to run coding agents on a remote server, without watching them all the time. An agent with access to my whole file system, my keys and my logins is not safe to leave alone, and it is not safe when I watch it either.

Pre-alpha, Linux only. The documentation lives at [doriath.fnune.com](https://doriath.fnune.com).

```sh
base=https://github.com/fnune/doriath/releases/latest/download
curl -fLO "$base/doriath-linux-amd64" -fLO "$base/doriath-linux-amd64.sha256"
sha256sum -c doriath-linux-amd64.sha256
install -m 755 doriath-linux-amd64 ~/.local/bin/doriath
doriath doctor
```

- [Install](https://doriath.fnune.com/install/) also covers home-manager, NixOS and Go, and walks from there to a first session.
- [Architecture](https://doriath.fnune.com/architecture/) covers the jail, the proxy, approvals and repositories.
- [Threat model](https://doriath.fnune.com/threat-model/) says what doriath guards against, what it leaves open, and how other sandboxes handle the same threats.
- [Configuration](https://doriath.fnune.com/reference/configuration/) lists every key.

## Development

`nix develop` provides the toolchain. `just check` runs formatting, lint and the unit tests, and `just test-integration` the tests that start real jails. [docs/engineering.md](docs/engineering.md) sets how the code is written, and [AGENTS.md](AGENTS.md) adds notes for coding agents. The documentation site is in [site/](site/), with `just site-dev` to preview it.
