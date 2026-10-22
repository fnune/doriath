---
title: Configuration
description: Every key of profiles, modules and config.toml, and the files doriath writes.
---

doriath reads `~/.config/doriath`, or `$DORIATH_CONFIG_DIR`:

| File                   | Holds                                             |
| ---------------------- | ------------------------------------------------- |
| `config.toml`          | settings for doriath itself, such as approvals    |
| `profiles/<name>.toml` | what one kind of work can reach, and its secrets  |
| `modules/<name>.toml`  | reusable parts of profiles, shareable with a team |

doriath finds profiles in `profiles/` and in the folders inside it, including linked ones, so one link adds a whole repository of profiles, such as private ones that stay out of a public home-manager configuration: `ln -s ~/Development/doriath-profiles ~/.config/doriath/profiles/private`. A profile is named after its file, and two files with one name are an error. Folders whose names start with a dot, such as `.git`, are skipped.

A profile lists `modules`. doriath applies them in order, each module's own `modules` first, then the profile. A user module with a built-in's name replaces it. Lists such as `mounts` and `egress.allow` are merged, maps such as `env.set` too with later values winning, and for an `[[http]]` host that appears twice later fields win and later rules go first. Only profiles set `description` and `secrets`. Unknown keys are errors. doriath never writes profiles: approvals print the lines to add, because a profile may come from nix.

Built-in modules, described in [modules](/reference/modules/): `base`, `vcs` (commits in read-only repositories), `docs` (documentation sites that accept no anonymous writes), `nix`, `nix-daemon`, `go`, `node`, `playwright`, `podman`, `pre-commit`, `github` and `claude`.

## Profile keys

```toml
description = "One line for doriath profiles list"
modules = ["base", "vcs", "github", "claude"]
# Device nodes, such as the TPM. Top-level keys go before the first table.
devices = ["/dev/tpmrm0"]

# Where each secret comes from: a file with mode 600, a command that prints
# it, or an OAuth login. doriath reads each once per session and never shows
# it to the jail. Modules name the secrets they need; the profile says where
# they are.
[secrets.github]
command = ["rbw", "get", "github-my-app"]

# An OAuth login: run doriath login --profile NAME once, on the host. mcp names
# an MCP server, which tells doriath where to sign in; otherwise give issuer,
# client_id and scopes. Sessions get fresh access tokens; see "OAuth logins".
[secrets.linear]
oauth = { mcp = "https://mcp.linear.app/mcp" }

[secrets.agent-signing]
file = "~/.config/doriath/keys/agent-signing"

# Paths the jail sees, at the same path. mode is read (default), write or
# hide. See "Mounts" below.
[[mounts]]
path = "~/Documents/notes"
optional = true

[[mounts]]
path = "{repository}/web/dist"
mode = "write"

[[mounts]]
path = "{repository}/.env"
mode = "hide"

# Writable paths backed by a directory of the profile's own, which nothing
# outside the jail reads.
[[caches]]
path = "~/.cache/go-build"

[env]
# Host variables the jail may see. Everything else is dropped.
pass = ["PATH", "TERM"]
set = { GOFLAGS = "-mod=mod" }
# Directories in front of PATH. The home-manager module fills this from a
# profile's packages.
path_prepend = ["/nix/store/...-xvfb-21.1.24/bin"]

[egress]
# Hosts reachable on port 443 (and 80 for plain HTTP). "*.example.com"
# matches subdomains but not example.com itself.
allow = ["proxy.golang.org", "*.githubusercontent.com"]
# Host localhost ports the jail may reach over HTTP, and as raw TCP.
ports = [4200]
tcp_ports = [3306]

# Hosts only some programs may reach. A bare name matches a program under a
# read-only system path such as /nix/store; a path is a glob that may start
# with ~/. doriath warns about a path the agent can write.
[[egress.programs]]
binaries = ["~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"]
allow = ["js.stripe.com"]

# A host whose TLS the proxy terminates, to add a credential and apply rules
# per request.
[[http]]
host = "api.github.com"
# scheme is bearer, token, or basic with username. binaries limits the
# credential to these programs, matched like egress.programs.
credential = { secret = "github", scheme = "bearer", binaries = ["gh"] }
# For requests no rule matches: allow, approve or deny. Hosts with a
# credential default to approve, others to allow.
default = "approve"

# The first matching rule wins. In path, "*" matches one segment and a
# trailing "**" the rest. A rule can also require graphql (operation, and
# top-level fields by name), a header, mcp_tools (MCP tools called, by glob),
# or body_contains (strings, also inside JSON). Bodies over 1 MB or compressed are refused for rules that read them.
[[http.rules]]
method = "POST"
path = "/repos/*/*/releases"
action = "approve"
summary = "Create a GitHub release"

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "mutation", fields = ["mergePullRequest"] }
action = "approve"
summary = "Merge a pull request"

[[http.rules]]
method = "*"
path = "/**"
header = "x-api-key"
action = "deny"

# MCP servers the agent may use. See "MCP servers".
[[mcp]]
name = "bazel"
command = ["bazel-mcp", "--stdio"]

[[mcp]]
name = "notion"
url = "https://mcp.notion.com/mcp"
secret = "notion"
# Tools, by name or glob, to hold for your approval or refuse. Others are
# allowed, or held with default = "approve" and an allow list.
approve = ["notion-create-*", "notion-update-*"]
deny = ["notion-delete-*"]

[secrets.notion]
command = ["rbw", "get", "notion-mcp"]

# An agent-only SSH key, named as a secret. It signs git commits and refuses
# SSH logins.
[signing]
key = "agent-signing"

# A podman service behind a broker that checks each API call. See "Containers".
[podman]
enabled = true
images = ["ghcr.io/acme/*"]

# The system nix daemon. Its builds run outside the jail, without the
# allowlist, so only the nix-daemon module turns it on.
[nix]
daemon = false

# Writable git and jj stores in read-only repositories. The vcs module turns
# it on. See "Repositories".
[vcs]
store = true

# Loosen the seccomp and Landlock limits for tools that need it.
[hardening]
namespaces = false   # nested sandboxes such as bubblewrap
ptrace = false       # debuggers
landlock = true

# A systemd user scope per session. tasks defaults to 8192 (0 is no limit),
# memory to 75% of RAM, and cpu is unset (200% is two cores).
[limits]
tasks = 8192
memory = "75%"
cpu = "200%"

# Settings for the claude adapter. The claude module gives the profile its
# own ~/.claude, with your CLAUDE.md, settings, skills and plugins
# read-only, and a login of its own: run /login in a session.
[claude]
disable_connectors = true
denied_mcp_servers = ["claude.ai Gmail"]
statusline = true
ask = ["mcp__claude-in-chrome__javascript_tool"]
deny = []
# How long a permission prompt waits for you before Claude shows its own.
approval_timeout = "60s"
```

## Mounts

Two placeholders resolve when a session starts, so one profile serves many projects: `{current}` is where `doriath run` starts (or `--current DIR`), and `{repository}` is the root of the git or jj repository that holds it. Entries with `{repository}` are skipped outside a repository.

doriath and modules add entries of their own:

| Entry                            | Mode    | From     | Kind    |
| -------------------------------- | ------- | -------- | ------- |
| `{current}`                      | `read`  | doriath  | default |
| `{repository}`                   | `read`  | `vcs`    | default |
| the repository's store           | `write` | `vcs`    | grant   |
| `{repository}/.claude/worktrees` | `write` | `claude` | grant   |

Entries combine by least privilege:

- A default yields to any entry for its path or a directory above it.
- Otherwise the lowest privilege wins on the same path: `hide`, then `read`, then `write`.
- A deeper path applies within its subtree: `write` inside a `read` repository, or `hide` inside a `write` directory.
- doriath creates a missing writable entry inside the repository, such as a worktree directory.

`write` changes your files in place, but git's and jj's config, hooks and info stay read-only, because git runs what they name. doriath creates the ones that are missing before the session and leaves them there, empty, so the agent cannot create them: `.git/hooks`, `info`, `config.worktree` and `objects/info/alternates`, `.jj/repo/config.toml`, and a `.git/commondir` that holds `.`, which names `.git` itself. doriath also refuses to start when a mount, or a path in a repository it guards, goes through a symlink inside a directory the jail can write, because an agent could have put the link there in an earlier session; a symlink elsewhere, such as `~/.nix-profile`, mounts what it points to. `hide` shows an empty directory or file, also to containers. A hidden path that does not exist yet inside a writable mount gets an empty placeholder for the session, so the agent cannot create it either; doriath removes it afterwards. doriath refuses `/`, the home directory and any directory above it, in any mode, and a writable mount under `/nix/store`, `/usr`, `/bin`, `/lib` or `/opt`, whose programs get credentials by name.

## Repositories

With `[vcs] store = true`, each git or jj repository in the session gets a writable store, so the agent commits, branches and adds worktrees while your checkout stays read-only:

| Repository | Writable                                                                                                                          | Read-only                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| git        | `.git/objects`, `refs`, `logs`, `worktrees`, `lfs`, and the same in submodules                                                    | the rest of `.git`, such as `config`, `hooks`, `info` and `HEAD`, and each worktree's `commondir` |
| jj         | `.jj/working_copy`, and in `.jj/repo` the `index`, `op_heads`, `op_store`, `submodule_store`, `workspace_store` and `store/extra` | `.jj/repo/config.toml`, `store/git_target`, `store/type`, and jj's git store as above             |

At the end, doriath removes LFS objects written during the session whose content does not match their name, since your checkout takes a file's content from the object with that name. `rr-cache` stays read-only, so the agent cannot plant a merge resolution that your next merge applies.

Starting in a linked git worktree or a secondary jj workspace mounts the main repository's store the same way. Because `.git` itself stays read-only, `git branch -d` fails in the jail. For a colocated jj repository, doriath turns on git's `relativeWorktrees` extension once, as jj's first workspace would.

doriath records your branches and bookmarks when a session starts. Existing packs, which hold nearly all of the history, are read-only in the jail for the session, and doriath keeps a copy of the loose objects, so neither deleting nor rewriting objects in place survives the end step. `git gc` in the jail cannot remove old packs, and its background runs warn about it. At the end it keeps the start value of each branch the agent moved as `refs/doriath/<session>/<branch>`, and repairs each worktree the agent added: its `.git` file and `commondir` point back at your repository, and a planted `config.worktree` goes. Until the session ends, an agent worktree is the agent's; do not run git in it.

- `doriath restore SESSION` puts moved branches and bookmarks back. It never runs by itself, because doriath cannot tell the agent's moves from yours.
- `doriath clean` removes, after you confirm, agent worktrees already in the default branch and old backups. `doriath clean --caches PROFILE` removes a profile's caches.

## Approvals

A request a rule holds, a host the profile does not name, and a path the agent asks to write all become approvals. [Answering requests](/guides/approvals/) covers how they wait and where you answer them; `host_wait` under [config.toml keys](#configtoml-keys) sets how long the agent waits.

The agent can ask to write only a path it already sees; a request never shows it something new. `doriath grant write` on the host can also attach a directory the jail does not see, which makes its contents readable too. doriath refuses, before asking, a path through a symlink, inside `.git` or `.jj`, hidden by the profile, a system path including `/var/tmp`, outside what Landlock allowed at the start (the home directory, `/tmp` and the writable mounts), or one of `.ssh`, `.gnupg`, `.aws`, `.config/gh`, `.claude`, `.local/share/keyrings`, `.password-store`, the config of git and jj (`.gitconfig`, `.config/git`, `.config/jj`), the nix and home-manager profiles under `.local/state`, and doriath's own configuration, state and cache. Repositories inside a granted path keep the read-only control files of a `write` mount. Containers started after a grant may bind the path writable.

## MCP servers

`[[mcp]]` lists the MCP servers an agent may use, for every agent doriath supports. Your own MCP servers stay out of the jail; only the profile's are there.

- A local server (`command`, optional `env`) runs inside the jail like any program, under its limits. Its `env` is visible to the agent, so keep secrets out of it.
- A remote server (`url`, https) is reached through the proxy. With `secret`, doriath intercepts its host and adds the secret as a bearer token, so the agent never holds it, and `[[http]]` rules for the host apply as for any other. Without one, doriath allows the host and leaves its traffic alone.

For a remote server, `approve` and `deny` hold or refuse tools by name or glob, and `allow` with `default = "approve"` holds every tool but the listed ones. doriath reads each request's JSON-RPC body, on any path of the host: a held call becomes an approval such as "Call notion tool notion-create-pages", with the arguments shown, and a batch is held if any call in it is. On a host doriath intercepts for a server (with a secret or holds), the endpoint's own traffic that calls no tool is allowed, and everything else, including other paths and bodies doriath cannot read as JSON-RPC, waits for approval, as on any credentialed host. A module can ship a server with its holds, and the profile adds the secret. A local server talks to the agent where doriath cannot see, so its tools cannot be held.

doriath writes the list to `/run/doriath/mcp.json` in the common `mcpServers` format, and the agent's adapter points the agent at it, for example with `--mcp-config` for Claude Code. A repository's own `.mcp.json` still applies. A server that signs in with OAuth takes an `oauth` secret; see "OAuth logins".

## OAuth logins

A secret with `oauth` is a login that doriath keeps on the host. `doriath login --profile NAME` signs in to each OAuth secret of the profile not signed in yet, or to the one you name: doriath opens the sign-in page in your browser and listens for the answer on the host's loopback address, which the jail cannot reach. With `mcp`, doriath discovers the sign-in server from the MCP server and registers itself as a client; with `issuer`, it signs in as `client_id` with `scopes`. Sessions then get a fresh access token for every request that uses the secret, refreshed as it expires, and the proxy adds it, so the agent never holds a token. If the refresh token stops working, doriath says to run `doriath login` again.

Tokens are stored in `~/.local/state/doriath/oauth/<profile>/<name>.json`, mode 600, outside the jail. The sign-in uses the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) for discovery and client registration, and `golang.org/x/oauth2` for PKCE and refresh.

## Containers

`[podman] images` lists the images containers may use, as [`path.Match`](https://pkg.go.dev/path#Match) globs over full references such as `docker.io/library/postgres:16`. Short names expand as Docker does, `*` does not cross `/`, and a pattern without a tag matches every tag. The podman module allows `docker.io/library/*`, `localhost/*`, Playwright's images and Testcontainers' helpers; `["*"]` allows any image.

The first pull of a tag records its digest in `~/.local/state/doriath/images/<profile>.json`. When the tag later resolves to another digest, doriath asks you before the pull, and containers of a pinned tag run the pinned digest. Delete a line to trust a tag again.

Containers may bind only what the profile mounts, with the same limits. Privileged containers, added capabilities, devices, host namespaces other than the network, and image pushes without approval are refused.

## config.toml keys

```toml
# Show approvals as desktop notifications with buttons.
[approvals]
desktop = true
# How long a held request waits for you before the agent gets an error.
# Default 2m with desktop notifications and 0s without. At most 1h.
host_wait = "2m"
```

## Files doriath writes

| Path                                      | What                                                                                                 |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `~/.local/state/doriath/audit.jsonl`      | Every session, egress decision and approval; read it with `doriath log`, or lnav with `contrib/lnav` |
| `~/.local/state/doriath/images/`          | Container image digests per profile                                                                  |
| `~/.local/state/doriath/oauth/`           | OAuth logins per profile, with their refresh tokens                                                  |
| `~/.local/state/doriath/web-token`        | The token of the approvals page                                                                      |
| `~/.local/state/doriath/backups/`         | Branches each session started with, and object hardlinks until it ends                               |
| `~/.cache/doriath/agents/<profile>/`      | The profile's caches, `/tmp`, Claude state and container storage                                     |
| `$XDG_RUNTIME_DIR/doriath/sessions/<id>/` | Sockets and generated files of a running session                                                     |
