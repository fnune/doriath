# Doriath

Doriath runs a coding agent such as Claude Code in a jail on your Linux machine, and sends every request it makes through a proxy that follows the rules of a profile you write. Tokens stay in the proxy, and merges, pushes and unknown hosts wait for your answer.

I build doriath because I want to run coding agents on a remote server, without watching them all the time. An agent with access to my whole file system, my keys and my logins is not safe to leave alone, and it is not safe when I watch it either.

Pre-alpha, Linux only. A macOS version is possible, but out of scope while I build doriath for my own use. The documentation lives at [doriath.fnune.com](https://doriath.fnune.com).

- [Install](https://doriath.fnune.com/install/) covers the release binary, home-manager, NixOS and Go, and walks from there to a first session.
- [Architecture](https://doriath.fnune.com/architecture/) covers the jail, the proxy, approvals and repositories.
- [Threat model](https://doriath.fnune.com/threat-model/) says what doriath guards against, what it leaves open, and how other sandboxes handle the same threats.
- [Configuration](https://doriath.fnune.com/reference/configuration/) lists every key.

## Install and run

Download the static release binary for `amd64` or `arm64`, check it and put it on your `PATH`:

```sh
base=https://github.com/fnune/doriath/releases/latest/download
curl -fLO "$base/doriath-linux-amd64" -fLO "$base/doriath-linux-amd64.sha256"
sha256sum -c doriath-linux-amd64.sha256
install -m 755 doriath-linux-amd64 ~/.local/bin/doriath
```

Write a profile that lists the modules of your tools, then run the agent in a jail with it. The [Install](https://doriath.fnune.com/install/) page shows how to write the profile.

```sh
doriath profiles edit my-app
doriath run --profile my-app -- claude
doriath approvals
```

The second command starts Claude Code in the jail of the profile `my-app`. The third command lists the requests that wait for your answer.

## Development

`nix develop` provides the toolchain. `just check` runs formatting, lint and the unit tests, and `just test-integration` the tests that start real jails. [docs/engineering.md](docs/engineering.md) sets how the code is written, and [AGENTS.md](AGENTS.md) adds notes for coding agents. The documentation site is in [site/](site/), with `just site-dev` to preview it.
