---
title: Configuration
description: Every key of profiles, modules and config.toml, and the files doriath writes.
---

doriath reads `~/.config/doriath`, or `$DORIATH_CONFIG_DIR` if you set it:

| File                   | Holds                                             |
| ---------------------- | ------------------------------------------------- |
| `config.toml`          | settings for doriath itself, such as approvals    |
| `profiles/<name>.toml` | what one kind of work can reach, and its secrets  |
| `modules/<name>.toml`  | reusable parts of profiles, shareable with a team |

doriath also finds profiles in the folders inside `profiles/`, and follows symlinks. Thus one symlink can add a repository of profiles, such as private profiles that stay out of a public home-manager configuration:

```sh
ln -s ~/Development/doriath-profiles ~/.config/doriath/profiles/private
```

The file name is the profile name, and two files with the same name are an error. doriath skips folders whose names start with a dot, such as `.git`.

doriath never writes to profiles, because a profile can come from nix. An approval prints the lines to add instead.

## Profiles and modules

A profile is an identity: it holds secrets, whose commands run on your machine, and it owns state, such as caches, the agent's login and image pins. A module is data only: it holds no secrets and no state, so doriath can ship modules and a team can share them.

A profile lists its `modules`, which the [modules](/reference/modules/) page describes. A session can also join profiles with `+`, as [composed profiles](#composed-profiles) describes. Both build one list of layers: each profile's modules in order, each module after its own `modules`, then the profile, and then the next profile in the same way. One set of rules merges the layers:

- Lists, such as `mounts` and `egress.allow`, merge.
- Maps, such as `env.set`, merge, and later values win.
- If an `[[http]]` host occurs two times, later fields win and later rules go first.
- Where two layers give the same path, the lesser access holds, as [mounts](#mounts) describes.
- Unknown keys are errors.

What differs between the two:

- Only profiles set `secrets`. A module's `description` is the line that `doriath modules list` shows. Two profiles that give one secret different sources, or that sign with different keys, are refused.
- A module names each secret that it hands to a credential, to `[signing]` or to an MCP server in `uses_secrets`, such as `uses_secrets = ["github"]`. The profile gives the secret's source. Thus a module cannot send a profile's token to another host without saying so, and `doriath profiles show` lists each secret with the modules that use it.
- A user module cannot have the name of a built-in module. Profiles with such a module do not load.
- State belongs to the session's profiles: a composed session has its own caches and agent login.

## Profile keys

This example shows every key of a profile. The sections after it give the details.

```toml
description = "One line for doriath profiles list"
modules = ["vcs-readwrite", "github", "claude"]
# Device nodes, such as the TPM.
# Top-level keys go before the first table.
devices = ["/dev/tpmrm0"]

# The source of each secret: a file with mode 600, a command that prints it,
# or an OAuth login. doriath reads it when the session starts, and the
# jail never sees it. required = true stops the session when the
# secret fails. See "Secrets".
[secrets.github]
command = ["rbw", "get", "github-my-app"]
required = true

# An OAuth login. Run doriath profiles login NAME one time, on the host.
# mcp names an MCP server, which tells doriath where to sign in.
# Without mcp, give issuer, client_id and scopes. See "OAuth logins".
[secrets.linear]
oauth = { mcp = "https://mcp.linear.app/mcp" }

[secrets.agent-signing]
file = "~/.config/doriath/keys/agent-signing"

# Paths that the jail sees, at the same path.
# mode is read (the default), write or hide. missing is error (the
# default), skip or hold. See "Mounts".
[[mounts]]
path = "~/Documents/notes"
missing = "skip"

[[mounts]]
path = "{repository}/web/dist"
mode = "write"

[[mounts]]
path = "{repository}/.env"
mode = "hide"

# How doriath request edit changes a read-only file. A text edit always
# waits for you. See "Edits".
[[mounts]]
path = "{repository}/.envrc"
edit = { format = "text" }

# Writable paths in a directory of the profile.
# Nothing outside the jail reads them.
[[caches]]
path = "~/.cache/go-build"

[env]
# Host variables that the jail sees. doriath drops all others, but always
# passes PATH and the terminal and locale variables.
pass = ["DEBUG"]
set = { GOFLAGS = "-mod=mod" }
# Directories in front of PATH.
# The home-manager module fills this from the packages of a profile.
path_prepend = ["/nix/store/...-xvfb-21.1.24/bin"]

[egress]
# Hosts that the jail can reach on port 443, and on 80 for plain HTTP.
# "*.example.com" matches subdomains, but not example.com.
# host:port gives a different port. The connection must use HTTP or TLS.
allow = ["proxy.golang.org", "*.githubusercontent.com", "git.example.org:3000"]
# Hosts refused at once, without asking you, unless an allow entry names
# them too. The claude module refuses downloads.claude.ai this way.
deny = ["telemetry.example.com"]
# What a host is, shown on the request that asks you to allow it. A module
# names the hosts of its tool this way.
notes = { "telemetry.example.com" = "The tool reports usage to this host." }
# Localhost ports of the host that the jail can reach over HTTP,
# and as raw TCP.
ports = [4200]
tcp_ports = [3306]

# Hosts that only some programs can reach.
# A bare name matches a program under a read-only system path, such as
# /nix/store. A path is a glob, and it can start with ~/. doriath pins the
# files that a path names when the session starts: another file there, a
# changed file, or code loaded from outside the system paths gets nothing.
[[egress.programs]]
binaries = ["~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"]
allow = ["js.stripe.com"]

# A host where the proxy terminates TLS, to add a credential and to apply
# rules to each request. host can be a pattern, such as *.example.com, and
# only then narrows it to some hosts or patterns, for example the region of
# a profile on a module's *.amazonaws.com.
[[http]]
host = "api.github.com"
# scheme is bearer, token, basic with username, header with the name of
# a header, such as PRIVATE-TOKEN, or sigv4. With sigv4, the agent signs
# AWS requests with placeholder keys, and the proxy signs them again with
# the secret, which is the JSON that credential_process prints.
# binaries gives the credential only to these programs, as in
# egress.programs. A rule can have its own credential.
credential = { secret = "github", scheme = "bearer", binaries = ["gh"] }
# The action for requests that match no rule: allow, approve or deny.
# Hosts with a credential default to approve, other hosts to allow.
default = "approve"
# Path prefixes that name one repository, so that an allow for the session
# covers only that repository. git paths, such as
# /owner/repo.git/git-receive-pack, name their repository without this key.
repositories = ["/repos/*/*"]

# The first rule that matches wins.
# In path, "*" matches one segment and "**" any number of segments,
# such as "/**/git-receive-pack".
# A rule can also require graphql (the operation, and top-level fields),
# a header, mcp_tools (MCP tools by glob), or body_contains (strings, also
# inside JSON, where spaces and the case of keys do not count). Rules that
# read the body refuse bodies over 1 MB and compressed bodies.
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

# A git host. With ssh, git in the jail sends the SSH remotes of the host,
# such as git@github.com:owner/repo, over HTTPS through the proxy. hosts
# names other SSH hosts of the forge, such as ssh.bitbucket.org.
[[http]]
host = "github.com"
credential = { secret = "github", scheme = "basic", username = "x-access-token", binaries = ["git"] }
ssh = { user = "git", port = 22, hosts = ["ssh.github.com"] }

# Links the agent may open in your browser. action is allow, approve
# (the default) or deny. forward_redirect forwards the loopback port of
# the link's redirect_uri into the jail, so that a sign-in finishes there.
# See "Links".
[[open]]
host = "login.example.com"
path = "/oauth/authorize"
action = "allow"
forward_redirect = true

# MCP servers that the agent can use. See "MCP servers".
[[mcp]]
name = "bazel"
command = ["bazel-mcp", "--stdio"]

[[mcp]]
name = "notion"
url = "https://mcp.notion.com/mcp"
secret = "notion"
# Tools, by name or glob, to hold for your approval or to refuse.
# doriath allows other tools, or holds them with default = "approve"
# and an allow list.
approve = ["notion-create-*", "notion-update-*"]
deny = ["notion-delete-*"]

[secrets.notion]
command = ["rbw", "get", "notion-mcp"]

# An SSH key for the agent only, named as a secret.
# It signs git and jj commits and refuses SSH logins. If your own git or jj
# config signs commits, a profile without a key does not start: give it a
# key, or set enable = false in place of key to commit unsigned.
[signing]
key = "agent-signing"

# A podman service behind a broker that checks each API call.
# See "Containers".
[podman]
enabled = true
images = ["ghcr.io/acme/*"]

# The system nix daemon. Its builds run outside the jail, without the
# allowlist. Thus only the nix-daemon module turns it on.
[nix]
daemon = false

# Writable git and jj stores in read-only repositories.
# vcs-readwrite and vcs-readonly turn it on. See "Repositories".
[vcs]
store = true

# Images from your clipboard, each read after you allow it. Text never
# reaches the jail. The clipboard module turns it on.
[clipboard]
images = true

# Make the seccomp and Landlock limits less strict for tools that need it.
[hardening]
namespaces = false   # nested sandboxes such as bubblewrap
ptrace = false       # debuggers
landlock = true

# A systemd user scope for each session. tasks defaults to 8192
# (0 is no limit), memory to 75% of RAM. cpu has no default
# (200% is two cores).
[limits]
tasks = 8192
memory = "75%"
cpu = "200%"

# Settings for every agent. instructions names the agent's own
# instructions files: the jail shows each as your file followed by what
# the session allows, so the agent knows the jail from its start.
[agent]
instructions = ["~/.codex/AGENTS.md"]

# Settings for the claude adapter. The claude module gives the profile its
# own ~/.claude, with your CLAUDE.md, settings, skills and plugins
# read-only, and its own login: run /login in a session.
[claude]
disable_connectors = true
denied_mcp_servers = ["claude.ai Gmail"]
# When set, the only connectors and MCP servers that Claude can use, by
# URL or name, besides the [[mcp]] servers of the profile.
allowed_mcp_servers = []
ask = ["mcp__claude-in-chrome__javascript_tool"]
deny = []
```

## Composed profiles

A session can use more than one profile, joined with `+`, such as `doriath run --profile my-app+deploy`. A profile for one task, such as deploying, then adds what that task needs to the profile of the project. Each profile applies over the ones before it, with the rules of [profiles and modules](#profiles-and-modules).

- A secret keeps the login of the profile that gives it, so `doriath profiles login my-app linear` also serves `my-app+deploy`.
- The composed session has its own caches and its own agent login, under the joined name. A session that holds deploy credentials cannot leave files in the caches that the project's own sessions trust.

`doriath profiles show my-app+deploy` shows the result, with the profile behind each entry. To use one composition for a project each time, name its profiles in the project's [`.envrc`](/guides/direnv/), such as `use doriath my-app deploy`.

## Repository profiles

A repository can keep profiles for its project in a `.doriath` folder at its root. A team commits them, so that each person gets the hosts, mounts and caches of the project.

Name a repository profile with `repo:` and its file name. For example, `repo:dev` is `.doriath/dev.toml` in the repository that holds `{current}`. It runs alone, or [composed](#composed-profiles) with your own profiles:

```sh
doriath run --profile my-app+repo:dev -- claude
```

- A repository profile cannot set a secret `command`, because the command would run on your machine with your environment, and the checkout may have written it. Keep secret commands in a profile of your own, and compose the two. A secret `file` is allowed. doriath asks you before it uses a repository profile, and again when it gives more. See [allowed profiles](#allowed-profiles).
- The `repo:` prefix keeps repository profiles apart from your own. A repository cannot replace one of your profiles or modules.
- A repository profile cannot change where your secrets go. It can hand out only the secrets it defines, and it cannot add rules to an `[[http]]` host that your profiles or modules give a credential, replace one of their `[[mcp]]` servers, or define a secret with the name of one of theirs. Put such rules in a profile of your own.
- A repository profile cannot mount your keys, logins, git and jj config, or the configuration, state and cache of doriath. It can hide them.
- In an [edit](#edits) `safe` list, a repository profile cannot name a git setting that runs a program or sends data to another place, such as `core.hookspath`, `credential.*`, `url.*`, `include.*` or `remote.*`.
- A repository profile cannot go in a `modules` list.
- A missing repository profile is an error, also outside a repository.
- Each repository has its own caches, logins and image pins for its repository profiles, also when two repositories use the same name.
- For settings of one computer, put them in your own profile. Or put them in a profile that `.gitignore` lists, such as `.doriath/my-dev.toml`, and name both: `my-app+repo:dev+repo:my-dev`.

The jail shows `.doriath` read-only, also in a writable repository, so that the agent cannot change what its next session loads. If the folder is missing, doriath holds its place for the session.

## Allowed profiles

doriath asks you before the first session of each profile in each repository. It shows what the profile gives the jail, and starts only after you answer `y`. The summary lists the mounts, caches, devices, hosts, environment, MCP servers, images and secrets by name. Below them it lists what decides where a secret goes and what the jail may do beyond its mounts: the command, file or login behind each secret, each credential with the host and programs it reaches, each host `default`, the links the browser opens, and settings such as `nix.daemon`, `hardening` and the safe edits. Read those lines with care when the profile comes from a repository.

```txt
You have not allowed profile my-app in /home/me/src/my-app yet. It gives the jail:
...
Allow? [y/N]
```

doriath keeps what you allowed. When the profile later gives more, the next session shows only the changed lines and asks again. This covers your own edits, a profile from a pull or a merge, and a new version of a built-in module. A profile gives more when it adds a line, and also when it loses a line that held the agent back: a `deny` or `approve` rule, a hidden path, the `binaries` or `only` of a credential, a host `default`, or an agent's own refusals. Such lines show with a `-`. A profile that only loses hosts, mounts or allow rules starts without a question.

```txt
Profile my-app in /home/me/src/my-app gives the jail more than when you allowed it:

  + Egress.Allow: evil.example
  + Mounts[{repository}].Mode: write
```

A session without a terminal, such as one that an editor starts, cannot ask. It stops and prints the command that allows the profile. Run it on the host:

```sh
doriath profiles allow my-app --current ~/src/my-app
```

## Secrets

A secret has a name that you select, and a source under `[secrets.NAME]`: a `file` with mode 600, a `command` that prints it, or an [`oauth` login](#oauth-logins). These keys refer to a secret by its name:

| Key                          | Uses the secret as                       |
| ---------------------------- | ---------------------------------------- |
| `[[http]] credential.secret` | the credential the proxy adds for a host |
| `[[mcp]] secret`             | the bearer token for a remote MCP server |
| `[signing] key`              | the agent's SSH key for signing commits  |

doriath reads each file and command secret when the session starts, before the agent. A command gets your terminal, so a password manager can ask for its password there. Before the command starts, doriath prints the name of the secret and the command, so that you can see that the prompt comes from your profile. For example, Bitwarden's `bw` asks one time for each session:

```toml
[secrets.github]
command = ["sh", "-c", "bw get password github-my-app --session \"$(bw unlock --raw)\""]
```

A short-lived credential needs a new value during the session. doriath runs the command again in two cases:

- The output is JSON with an `Expiration`, in the `credential_process` format that AWS tools print. doriath runs the command again 5 minutes before that time.
- The secret has `refresh`, for a command that prints only a token. For example, Google Cloud access tokens last one hour:

```toml
[secrets.gcp]
command = ["gcloud", "auth", "print-access-token"]
refresh = "45m"
```

A command that runs again during the session does not get your terminal, because the agent uses it. If it fails, doriath keeps the old value until it expires, and tries again every 30 seconds.

A session starts without a secret that fails, so that one missing login does not block the work that does not need it. doriath prints the error and what fails without the secret before the agent starts:

- The proxy refuses each request that needs the secret, and tells the agent to ask you to fix it.
- `doriath status` in the jail lists the secret, its error and the hosts that need it. This error does not show the output of the command, because a command can print its secret when it fails. You see the output on the host.
- doriath tries a command or a file again when a request needs it, at most every 30 seconds and without your terminal. Thus a login on the host, such as `aws sso login`, starts to work during the session.

To give a running session a value yourself, run [`doriath secrets provide`](/reference/commands/#doriath-secrets-provide) on the host.

Set `required = true` on a secret to stop the session when the secret fails. The secret of `[signing] key` is always required, because the agent cannot commit without it. `doriath doctor --secrets` marks an optional secret that fails with `·`, and a required one with `✕`.

doriath checks that the agent cannot write the program that a command starts. Here that program is `sh`, so keep `bw` at a path that the agent cannot write, such as the Nix store.

A module can name a secret without its source, and the profile gives the source. For example, a profile with the `github` module needs `[secrets.github]`. If a credential or signing key names a secret without a source, doriath refuses the profile and gives the table to add.

## Mounts

Two placeholders resolve when a session starts, thus one profile can serve many projects:

- `{current}` is the folder where `doriath run` starts, or the folder of `--current DIR`.
- `{repository}` is the root of the git or jj repository that holds it. Outside a repository, doriath skips the entries with `{repository}`.

doriath and modules add these entries:

| Entry                            | Mode    | From                            | Kind    |
| -------------------------------- | ------- | ------------------------------- | ------- |
| `{current}`                      | `read`  | doriath                         | default |
| `{repository}`                   | `read`  | `vcs-readwrite`, `vcs-readonly` | default |
| `{repository}`                   | `write` | `vcs-readwrite`                 | grant   |
| `{repository}`                   | `read`  | `vcs-readonly`                  | grant   |
| the repository's store           | `write` | `vcs-readwrite`, `vcs-readonly` | grant   |
| `{repository}/.claude/worktrees` | `write` | `claude`                        | grant   |

Entries combine by least privilege:

- A default yields to all entries for its path or for a directory above it.
- Otherwise, on the same path, the lowest privilege wins: `hide`, then `read`, then `write`.
- A deeper path applies in its subtree: `write` in a `read` repository, or `hide` in a `write` directory.
- doriath creates a missing writable entry inside the repository, such as a worktree directory.

`write` changes your files in place, but the config, hooks and info of git and jj stay read-only, because git runs what they name. If these are missing, doriath creates them empty before the session, so that the agent cannot create them: `.git/hooks`, `info`, `remotes`, `branches`, `config.worktree` and `objects/info/alternates`, `.jj/repo/config.toml`, and a `.git/commondir` that holds `.`.

`hide` shows an empty directory or file, also to containers.

`missing` says what happens when the path does not exist:

- `error`, the default for `read` and `write`: the session does not start.
- `skip`: the jail leaves the path out.
- `hold`, the default for `hide`: inside a writable mount, doriath puts an empty file at the path for the session, or `{}` for a JSON file, so that tools can read it, so that the agent cannot create it there, and lists it in the repository's `info/exclude`, so that git and jj leave it out of commits. To give the file content, the agent runs [`doriath request edit`](#edits). doriath removes the placeholder at the end, unless someone wrote to it. Outside a writable mount, `hold` is `skip`.

Where two entries give the same path, the stricter `missing` holds: `error`, then `hold`, then `skip`.

doriath refuses to start if a mount, or a guarded path in a repository, goes through a symlink in a directory that the jail can write. An agent can put such a link there in an earlier session. Other symlinks, such as `~/.nix-profile`, mount their target.

A guarded path that is itself a symlink is an exception, because tools make such links: git-hooks.nix links `.pre-commit-config.yaml` into the Nix store, and jj links `.jj/repo/config.toml` to your jj config. No mount can make a symlink read-only, so doriath keeps the link in place instead:

- In a read-only mount, the link cannot change, and doriath leaves it as it is.
- In a writable mount, doriath records where the link points, and watches it. If the jail changes it, doriath puts the link back at once, sends a notification, and reports it at the end of the session and in `doriath status`.
- doriath refuses to start if the link points to a path that the jail can write, because the agent could then change what the link holds.

doriath also refuses `/`, the home directory and the directories above it, in all modes. It refuses writable mounts under `/nix/store`, `/usr`, `/bin`, `/lib` or `/opt`, because programs there get credentials by name.

## Home

The home directory in the jail is an empty folder on disk for each session, under `~/.cache/doriath/agents/<profile>/scratch/`. Mounts and caches show through it, and nothing else of your home does: tools in `~/.nix-profile` or `~/.local/bin` need a mount. Files that the agent writes anywhere else in the home stay for the session only, and doriath deletes them at the end.

When the session ends, doriath lists each folder there that holds more than 512 MB, such as `~/.cache/bazel-disk`. It prints the `[[caches]]` lines that keep the folder for later sessions.

## Edits

The agent can ask to change one file that is read-only in the jail, such as `.git/config` when git or jj cannot write it. It writes the whole new content to a file, and runs `doriath request edit PATH --reason TEXT < FILE`. doriath compares the new content with the file, shows you what changes, and writes it once if you allow it. The file stays read-only in the jail before and after.

The jail's `git` is a front for your git that makes these requests itself, for the settings git writes on its own. The upstream that `git push -u`, `git branch --set-upstream-to` or `git switch --track` records then reaches `.git/config` as the safe list allows, and `git remote add` asks you before the remote does.

An `edit` table on a read-only mount says how doriath compares the file:

- `format = "git-config"` compares settings as git reads them, without following includes. Comments and layout are no change, and doriath writes only the changed settings, never the agent's file.
- `format = "text"` compares the whole file, and shows you a line diff.

`safe` lists the settings that change without asking you, as `KEY = VALUE`. In a key, `*` matches anything. In a value, `*` matches anything but `/` and `:`, and `**` matches anything. Any other change waits for your answer, with the settings that are not on the list marked.

`{git}` stands for every git directory that doriath guards, submodules included. A mount of `{git}/config` gives only an edit rule, since doriath already keeps the file read-only. The [`vcs-readwrite` module](/reference/modules/#vcs-readwrite) sets one:

```toml
[[mounts]]
path = "{git}/config"
edit = { format = "git-config", safe = [
  "branch.*.remote = *",
  "branch.*.merge = refs/heads/**",
] }
```

Upstream tracking, as `git push -u` records it, then changes at once. jj workspaces need no setting: in the jail, git and jj record worktrees with absolute paths, which need no extension in `.git/config`. A setting that names a program, such as `core.fsmonitor`, a remote's URL, or a remote that the config does not define, waits for you. A read-only file without an `edit` table changes as text, and also waits for you.

## Repositories

With `[vcs] store = true`, each git or jj repository gets a writable store. The agent can commit, branch and add worktrees, and your checkout stays read-only:

| Repository | Writable                                                                                                                                                    | Read-only                                                                                                                                                                             |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| git        | `.git` and its submodule stores, such as `objects`, `refs`, `HEAD`, `index`, `packed-refs` and their lock files                                             | `config`, `config.worktree`, `hooks`, `info`, `remotes`, `branches`, `commondir`, `objects/info/alternates`, `rr-cache`, existing packs, and each worktree's `commondir` and `gitdir` |
| jj         | `.jj/working_copy`, and in `.jj/repo` the `index`, `op_heads`, `op_store`, `submodule_store`, `workspace_store`, `store/extra` and `git_import_export.lock` | the rest of `.jj/repo`, such as `config.toml`, `config-id`, `store/git_target` and `store/type`, and jj's git store as above                                                          |

In the jail, git reads a global config that doriath builds from yours, without credentials, URL rewrites, remotes, includes, hooks or settings that run a program. doriath copies in the files that git reads on your machine through that config: the global ignore rules, attributes and commit template, by default from `~/.config/git`. Without them, git and jj in the jail would track what your global ignore leaves out.

In a linked git worktree or a secondary jj workspace, doriath mounts the store of the main repository. Because `.git/config` stays read-only, git in the jail warns that it cannot remove a deleted branch's upstream settings. [Edits](#edits) lets the agent change them.

At the start, doriath records your branches and bookmarks, and copies the loose objects. Existing packs, which hold almost all of the history, stay read-only. Thus objects that the agent deletes or rewrites in place do not stay that way after the session. `git gc` in the jail cannot remove old packs, and its background runs warn about this.

At the end, doriath does these steps:

- It keeps the start value of each branch that the agent moved as `refs/doriath/<session>/<branch>`.
- It removes new LFS objects whose content does not match their name, because your checkout takes file content from the object with that name.
- It repairs each worktree that the agent added. The `.git` file and `commondir` point to your repository again, and doriath removes a planted `config.worktree`.
- It moves aside, to `NAME.doriath-<session>`, what the agent left in a store for git on your machine to act on: a rebase, cherry-pick or revert to continue, a new `rr-cache`, and a new submodule store. Until then, do not continue a rebase that the agent started.

Do not run git in an agent worktree until the session ends. `doriath restore SESSION [BRANCH...]` puts moved branches and bookmarks back. It never runs automatically, because doriath cannot tell the moves of the agent from your moves. [`doriath clean`](/reference/commands/#doriath-clean) removes old agent worktrees and backups.

## Approvals

[Answering requests](/guides/approvals/) tells which requests wait for you, and where you answer them. `host_wait` under [config.toml keys](#configtoml-keys) sets how long the agent waits.

The agent can ask to write a path, or to read a folder that the jail does not show. A path the jail does not show must exist.

doriath refuses these paths before it asks you:

- symlinks, and paths inside `.git` or `.jj`
- paths that the profile hides
- system paths, `/var/tmp` included
- paths outside what Landlock allowed at the start: the home directory, `/tmp` and the writable mounts
- `.ssh`, `.gnupg`, `.aws`, `.config/gh`, `.claude`, `.local/share/keyrings` and `.password-store`
- the config of git and jj: `.gitconfig`, `.config/git` and `.config/jj`
- the nix and home-manager profiles under `.local/state`, and the configuration, state and cache of doriath

Repositories in a granted path keep the read-only control files of a `write` mount. Containers that start after a grant can bind the path as writable.

## Links

The agent opens a link in your browser with `xdg-open`, `$BROWSER` or [`doriath request open`](/reference/commands/#doriath-request-open). doriath opens only `http` and `https` links, without a user name or password in them. Each link meets the first `[[open]]` rule whose host and path match it, the profile's rules before those of its modules:

- `allow` opens the link at once.
- `approve`, the default for a link that no rule names, asks you first. The request shows the whole link, because your browser sends all of it to the site, where you are signed in.
- `deny` refuses it.

A sign-in in the jail often opens a link whose `redirect_uri` sends your browser back to a port on `localhost`, where the tool waits for the answer. Your browser runs on your machine, so doriath forwards that port into the jail for five minutes. It does so for a link that you allow, and for a rule with `forward_redirect = true`. The agent modules allow their own sign-in pages this way, so `/login` in Claude Code works without a question. The forge modules allow links to their sites, where the agent can already send data through the forge's API.

## MCP servers

`[[mcp]]` lists the MCP servers of the profile, for all agents that doriath supports. Your own MCP servers stay outside the jail.

- A local server (`command`, optional `env`) runs in the jail with its limits. The agent can read its `env`, so do not put secrets there.
- A remote server (`url`, https) goes through the proxy. With `secret`, the proxy adds the secret as a bearer token to requests for the path of `url` only, and `[[http]]` rules for the host apply. Another server on the same host does not get the token. Without `secret`, doriath allows the host and does not change its traffic.

For a remote server, `approve` and `deny` hold or refuse tools by name or glob. `allow` with `default = "approve"` holds all tools except the listed ones. doriath reads the JSON-RPC body on the path of `url`. A tool in `deny` is refused on all paths of the host. A held call becomes an approval such as "Call notion tool notion-create-pages", with its arguments. If one call in a batch is held, doriath holds the batch.

If a server has a secret or holds, doriath intercepts its host. There, endpoint traffic that calls no tool goes through. All other traffic waits for approval, as on all hosts with a credential. This includes other paths, and bodies that doriath cannot read as JSON-RPC.

A module can supply a server with its holds, and the profile adds the secret. doriath cannot hold the tools of a local server, because the server talks to the agent where doriath cannot see the traffic.

Each adapter gives the list to its agent in the format of that agent, such as `--mcp-config` for Claude Code or `mcp_servers` in the config of Codex. doriath also writes the list to `/run/doriath/mcp.json` in the common `mcpServers` format, for an agent without an adapter. The `.mcp.json` of a repository also applies to Claude Code.

## OAuth logins

A secret with `oauth` is a login that doriath keeps on the host. To sign in, run this command on the host:

```sh
doriath profiles login NAME
```

The command signs in to each OAuth secret of the profile that has no login yet, or to the secret that you name. doriath opens the sign-in page in your browser, and gets the answer on the host loopback address, which the jail cannot reach.

- With `mcp`, doriath finds the sign-in server from the MCP server, and registers itself as a client.
- With `issuer`, doriath signs in as `client_id` with `scopes`.

In a session, doriath refuses the agent's own sign-in to a server that it holds a login for. A token that the agent got would stay in the jail, where the agent can read it. The server's metadata stays readable.

Each request that uses the secret gets a fresh access token, which the proxy adds. Thus the agent never holds a token. If the refresh token stops working, doriath tells you to run `doriath profiles login` again. Tokens are in `~/.local/state/doriath/oauth/<profile>/<name>.json`, with mode 600, outside the jail.

## Containers

`[podman] images` lists the images that containers can use, as [`path.Match`](https://pkg.go.dev/path#Match) globs over full references such as `docker.io/library/postgres:16`:

- Short names expand as in Docker.
- `*` does not match `/`.
- A pattern without a tag matches all tags.
- `["*"]` allows all images.

The podman module allows `docker.io/library/*`, `localhost/*`, the images of Playwright and the helpers of Testcontainers.

The first pull of a tag records its digest in `~/.local/state/doriath/images/<profile>.json`. If the tag later resolves to a different digest, doriath asks you before the pull. Containers of a pinned tag run the pinned digest. To trust a tag again, delete its line.

Containers can bind only what the profile mounts, with the same limits. doriath refuses privileged containers, added capabilities, devices, host namespaces other than the network, and image pushes without your approval.

## config.toml keys

```toml
# Show approvals as desktop notifications with buttons.
[approvals]
desktop = true
# How long a held request waits for you before the agent gets an error.
# The default is 2m with desktop notifications and 0s without them.
# The maximum is 1h.
host_wait = "2m"
# How long a permission prompt of the agent waits for you before the agent
# shows its own. The maximum is 1h.
tool_wait = "60s"

# While a session runs in a terminal, show "doriath · PROFILE" as the
# window title, so that tabs and panes tell sessions apart. The title
# before the session comes back when it ends.
#
# bar shows the session on the last row of your terminal, below the agent,
# with the profile, the session name, the hosts and the requests that wait
# for you. The agent gets one row less. With bar = false, doriath does not
# stand between the agent and your terminal: the agent gets it as it is.
[terminal]
title = true
bar = true
```

## Files doriath writes

| Path                                      | Holds                                                                                                 |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `~/.local/state/doriath/audit.jsonl`      | Every session, egress decision and approval. Read it with `doriath log`, or lnav with `contrib/lnav`. |
| `~/.local/state/doriath/images/`          | Container image digests for each profile                                                              |
| `~/.local/state/doriath/profiles/`        | What you allowed for each profile in each repository                                                  |
| `~/.local/state/doriath/oauth/`           | OAuth logins for each profile, with their refresh tokens                                              |
| `~/.local/state/doriath/web-token`        | The token of the approvals page                                                                       |
| `~/.local/state/doriath/backups/`         | The branches at the start of each session, and object hardlinks until the session ends                |
| `~/.cache/doriath/agents/<profile>/`      | The caches, `/tmp`, home, agent state and container storage of the profile                            |
| `$XDG_RUNTIME_DIR/doriath/sessions/<id>/` | Sockets and generated files of a running session                                                      |
