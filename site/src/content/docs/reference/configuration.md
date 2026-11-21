---
title: Configuration
description: Every key of profiles, modules and config.toml, and the files doriath writes.
---

doriath reads its configuration from `~/.config/doriath`, or from `$DORIATH_CONFIG_DIR` if you set it:

| File                   | Holds                                             |
| ---------------------- | ------------------------------------------------- |
| `config.toml`          | settings for doriath itself, such as approvals    |
| `profiles/<name>.toml` | what one kind of work can reach, and its secrets  |
| `modules/<name>.toml`  | reusable parts of profiles, shareable with a team |

doriath also reads profiles from the folders in `profiles/`, and follows symlinks. One symlink can thus add a repository of profiles, such as private profiles that stay out of a public home-manager configuration:

```sh
ln -s ~/Development/my-profiles ~/.config/doriath/profiles/private
```

The file name is the profile name. Two files with the same name are an error. doriath skips folders whose names start with a dot, such as `.git`.

doriath never writes to profiles, because a profile can come from Nix. An approval prints the lines to add.

## Profiles and modules

A profile holds secrets, whose commands run on your machine. It also owns state, such as caches, the agent's login and image pins. A module holds no secrets and no state, so doriath can ship modules and a team can share them.

A profile lists its `modules`, as [modules](/reference/modules/) describes. A session can join profiles with `+`, as [composed profiles](#composed-profiles) describes. doriath builds one list of layers: the modules of each profile in order, each module after its own `modules`, then the profile, then the next profile. These rules merge the layers:

- Lists, such as `mounts` and `egress.allow`, merge.
- Maps, such as `env.set`, merge, and later values win.
- If two layers name the same `[[http]]` host, later fields win and later rules go first.
- If two layers give the same path, the lesser access holds, as [mounts](#mounts) describes.
- Unknown keys are errors.

Profiles and modules differ in these ways:

- Only profiles set `secrets`. doriath refuses two profiles that give one secret different sources, or that sign with different keys.
- A module names in `uses_secrets` each secret that it gives to a credential, to `[signing]` or to an MCP server, such as `uses_secrets = ["github"]`. The profile gives the source. Thus a module cannot send a token to another host without saying so. `doriath profiles show` lists each secret with the modules that use it.
- A module's `description` is the line that `doriath modules list` shows.
- A user module cannot have the name of a built-in module. A profile with such a module does not load.

## Profile keys

This example shows every key of a profile. The sections after it give the details.

```toml
description = "One line for doriath profiles list"
modules = ["vcs-readwrite", "github", "claude"]
# Device nodes, such as the TPM.
# Top-level keys go before the first table.
devices = ["/dev/tpmrm0"]

# The source of each secret: a command that prints it, an entry in the
# keyring of your desktop, or an OAuth login. doriath reads it when the session starts, and the
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
keyring = true

# Paths that the jail shows, at the same path.
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

# Paths that requests for a path refuse, or warn on. A hold also stays
# read-only in each writable mount. See "Path lists".
[paths]
refuse = ["~/.config/rclone"]

[[paths.warn]]
path = "~/.config/hypr"
reason = "Hyprland runs the commands in its config when you log in."

[[paths.hold]]
path = "{repository}/.mise.local.toml"
reason = "mise runs its hooks when you enter the folder."
missing = "move"

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
# Hosts that doriath refuses at once, without a question, unless an allow
# entry names them too. The claude module refuses downloads.claude.ai
# this way.
deny = ["telemetry.example.com"]
# What a host is. The request for the host shows this note.
notes = { "telemetry.example.com" = "The tool reports usage to this host." }
# Localhost ports of the host that the jail can reach over HTTP,
# and as raw TCP.
ports = [4200]
tcp_ports = [3306]

# Hosts that only some programs can reach.
# A bare name matches a program under a read-only system path, such as
# /nix/store. A path is a glob, and it can start with ~/. doriath pins the
# files that a path names when the session starts. Another file there, a
# changed file, or code from outside the system paths gets nothing.
[[egress.programs]]
binaries = ["~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"]
allow = ["js.stripe.com"]

# A host where the proxy terminates TLS, to add a credential and to apply
# rules to each request. host can be a pattern, such as *.example.com.
# Then only narrows it to some hosts or patterns, for example to the region
# of a profile on the *.amazonaws.com of a module.
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
# a header, mcp_tools (MCP tools by glob), body_contains (strings, also
# inside JSON, where spaces and the case of keys do not count), or refs (the
# refs that a git push updates, such as "refs/heads/agent/**"). Rules that
# read the body refuse bodies over 1 MB and compressed bodies. See
# "Branches for the agent" on the Forges page for refs.
# summary names what a held request does, and is the title of its
# notification. subject is what it acts on, and link is a button that
# opens its page without an answer. In both, {1} to {9} are the segments
# of the request path, and {ref} is the branch or tag of a push of one
# ref. A link has a fixed https:// host.
[[http.rules]]
method = "PUT"
path = "/repos/*/*/pulls/*/merge"
action = "approve"
summary = "Merge pull request"
subject = "{3}#{5}"
link = { label = "Open PR", url = "https://github.com/{2}/{3}/pull/{5}" }

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "mutation", fields = ["mergePullRequest"] }
action = "approve"
summary = "Merge pull request"

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

# Links that the agent can open in your browser. action is allow, approve
# (the default) or deny. forward_redirect forwards the loopback port of
# the redirect_uri of the link into the jail, so that a sign-in finishes
# there. See "Links".
[[open]]
host = "login.example.com"
path = "/oauth/authorize"
action = "allow"
forward_redirect = true

# Ports of the jail that you reach from your machine during each session.
# port is 8080, or "HOST:JAIL" such as "8080:3000", in the order of
# podman -p. See "Forwards".
[[forward]]
name = "Docs preview"
port = "8080:3000"

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
# config signs commits, a profile without a key does not start. Give it a
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

# Zip and jar files, as globs. A program that a credential or egress entry
# names can load the native libraries that these files ship, although it
# unpacks them into a temporary folder. doriath reads the files when the
# session starts. The bazel module names the install base of Bazel.
# libraries are native libraries at a fixed path, which doriath pins like
# the files next to a named program.
[code]
archives = ["~/.cache/bazel/_bazel_*/install/*/A-server.jar"]
libraries = ["~/.cache/bazel/_bazel_*/install/*/libcpu_profiler.so"]

# Less strict seccomp and Landlock limits, for tools that need them.
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

# Settings for every agent. instructions names the instructions files of
# the agent. The jail shows each one as your file followed by what the
# session allows, so the agent knows the jail from its start.
[agent]
instructions = ["~/.codex/AGENTS.md"]

# Settings for the claude adapter. See the Claude Code page.
[claude]
disable_connectors = true
denied_mcp_servers = ["claude.ai Gmail"]
# When set, the only connectors and MCP servers that Claude can use, by
# URL or name, in addition to the [[mcp]] servers of the profile.
allowed_mcp_servers = []
ask = ["mcp__claude-in-chrome__javascript_tool"]
deny = []
```

## Composed profiles

A session can use more than one profile, joined with `+`, such as `doriath run --profile my-app+deploy`. A profile for one task, such as a deploy, then adds what the task needs to the profile of the project. Each profile applies over the profiles before it, with the rules of [profiles and modules](#profiles-and-modules).

- A secret keeps the login of the profile that gives it. Thus `doriath profiles login my-app linear` also serves `my-app+deploy`.
- The composed session has its own caches and agent login, under the joined name. Thus a session with deploy credentials cannot put files in the caches that the sessions of the project trust.

`doriath profiles show my-app+deploy` shows the result, with the profile behind each entry. To use one composition in a project each time, name its profiles in the [`.envrc`](/guides/direnv/) of the project, such as `use doriath my-app deploy`.

## Repository profiles

A repository can keep profiles for its project in a `.doriath` folder at its root. A team commits them, and each person gets the hosts, mounts and caches of the project.

Name a repository profile with `repo:` and its file name. For example, `repo:dev` is `.doriath/dev.toml` in the repository that holds `{current}`. It runs alone, or [composed](#composed-profiles) with your own profiles:

```sh
doriath run --profile my-app+repo:dev -- claude
```

These limits apply to a repository profile:

- It cannot set a secret `command`, because the command runs on your machine with your environment, and the checkout can change it. A secret with a login is allowed. Keep secret commands in your own profile, and compose the two.
- It cannot change where your secrets go. It gives out only the secrets that it defines. It cannot add rules to an `[[http]]` host that your profiles or modules give a credential, replace one of their `[[mcp]]` servers, or define a secret with the name of one of theirs.
- It cannot mount your keys, logins, git and jj config, or the configuration, state and cache of doriath. It can hide them.
- In an [edit](#edits) `safe` list, it cannot name a git setting that runs a program or sends data to another place, such as `core.hookspath`, `credential.*`, `url.*`, `include.*` or `remote.*`.
- It cannot replace one of your profiles or modules, and it cannot go in a `modules` list.
- A missing repository profile is an error, also outside a repository.
- Each repository has its own caches, logins and image pins for its repository profiles, also if two repositories use the same name.

doriath asks you before it uses a repository profile, and again when the profile gives more, as [allowed profiles](#allowed-profiles) describes. The jail shows `.doriath` read-only, also in a writable repository, so the agent cannot change what its next session loads. If the folder is missing, doriath holds its place for the session.

Put the settings of one computer in your own profile. Or put them in a profile that `.gitignore` lists, such as `.doriath/my-dev.toml`, and name both: `my-app+repo:dev+repo:my-dev`.

## Allowed profiles

doriath asks you before the first session of each profile in each repository. It shows what the profile gives the jail, and starts only after you answer `y`. The summary lists the mounts, caches, devices, hosts, environment, MCP servers, images and secrets by name.

Below the summary, doriath lists what decides where a secret goes and what the jail can do beyond its mounts:

- the command, keyring entry or login behind each secret
- each credential, with the host and programs that it reaches
- each host `default`, and the links that the browser opens
- settings such as `nix.daemon`, `hardening` and the safe edits

An `env.pass` name that can hold a credential, connect to a service on your machine or change the code that programs load shows in red, with the reason. doriath still passes it.

Read these lines with care when the profile comes from a repository.

```txt
You have not allowed profile my-app in /home/me/src/my-app yet. It gives the jail:
...
Allow? [y/N]
```

doriath keeps what you allowed. When the profile later gives more, the next session shows only the changed lines and asks again. This covers your own edits, a profile from a pull or a merge, and a new version of a built-in module.

A profile gives more when it adds a line. It also gives more when it loses a line that held the agent back: a `deny` or `approve` rule, a hidden path, the `binaries` or `only` of a credential, a host `default`, or a refusal of an agent adapter. Such lines show with a `-`. A profile that only loses hosts, mounts or allow rules starts without a question. So does a profile that only adds `deny` rules, because a `deny` rule can only refuse more, wherever it stands in its list.

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

A secret has a name that you choose, and a source under `[secrets.NAME]`: a `command` that prints the secret, an entry in the [keyring](#keyring-secrets) of your desktop, or an [`oauth` login](#oauth-logins). These keys use a secret by its name:

| Key                          | Uses the secret as                       |
| ---------------------------- | ---------------------------------------- |
| `[[http]] credential.secret` | the credential the proxy adds for a host |
| `[[mcp]] secret`             | the bearer token for a remote MCP server |
| `[signing] key`              | the agent's SSH key for signing commits  |

A module can name a secret without its source, and the profile gives the source. For example, a profile with the `github` module needs `[secrets.github]`. If a credential or a signing key names a secret without a source, doriath refuses the profile and prints the table to add.

doriath reads each command and keyring secret when the session starts, before the agent. A command gets your terminal, so a password manager can ask for its password there. doriath first prints the name of the secret and the command, so you can see that the prompt comes from your profile. For example, Bitwarden's `bw` asks one time for each session:

```toml
[secrets.github]
command = ["sh", "-c", "bw get password github-my-app --session \"$(bw unlock --raw)\""]
```

doriath checks that the agent cannot write the program that a command starts. Here that program is `sh`, so keep `bw` at a path that the agent cannot write, such as the Nix store.

A short-lived credential needs a new value during the session. doriath runs the command again in two cases:

- The output is JSON with an `Expiration`, in the `credential_process` format of AWS tools. doriath runs the command again 5 minutes before that time.
- The secret has `refresh`, for a command that prints only a token. For example, a Google Cloud access token lasts one hour:

```toml
[secrets.gcp]
command = ["gcloud", "auth", "print-access-token"]
refresh = "45m"
```

A command that runs again during the session does not get your terminal, because the agent has it. If the command fails, doriath keeps the old value until it expires, and tries again every 30 seconds.

A session starts without a secret that fails, so that one missing login does not stop other work. Before the agent starts, doriath prints the error and what fails without the secret. During the session:

- The proxy refuses each request that needs the secret, and tells the agent to ask you.
- `doriath status` in the jail lists the secret, its error and the hosts that need it. The error does not show the output of the command, because a command can print its secret when it fails. You see the output on the host.
- doriath reads a command or a file again when a request needs it, at most every 30 seconds and without your terminal. Thus a login on the host, such as `aws sso login`, starts to work during the session.
- [`doriath secrets provide`](/reference/commands/#doriath-secrets-provide) on the host gives the session a value.

Set `required = true` to stop the session when the secret fails. The secret of `[signing] key` is always required, because the agent cannot commit without it. `doriath doctor --secrets` marks an optional secret that fails with `·`, and a required one with `✕`.

## Mounts

These placeholders resolve when doriath loads a profile, so one profile can serve many projects and machines:

- `{current}` is the folder where `doriath run` starts, or the folder of `--current DIR`.
- `{repository}` is the root of the git or jj repository that holds `{current}`. Outside a repository, doriath skips the entries with `{repository}`.
- `{user}` is your login name, anywhere in a path. Some programs name a directory in `/tmp` after it. If doriath cannot find your login name, it skips the entries with `{user}`.

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

With `write`, the agent changes your files in place. The config, hooks and info of git and jj stay read-only, because git runs what they name. If these are missing, doriath creates them empty before the session, so the agent cannot create them: `.git/hooks`, `info`, `remotes`, `branches`, `config.worktree` and `objects/info/alternates`, `.jj/repo/config.toml`, and a `.git/commondir` that holds `.`.

`hide` shows an empty directory or file, also to containers.

`missing` sets what happens when the path does not exist:

- `error`, the default for `read` and `write`: the session does not start.
- `skip`: the jail leaves the path out.
- `hold`, the default for `hide`: inside a writable mount, doriath puts an empty file at the path for the session, or `{}` for a JSON file. Tools can read it, and the agent cannot create the file there. doriath lists the path in the `info/exclude` of the repository, so git and jj leave it out of commits. To give the file content, the agent runs [`doriath request edit`](#edits). At the end, doriath removes the empty file if nobody wrote to it. Outside a writable mount, `hold` is `skip`.

If two entries give the same path, the stricter `missing` holds: `error`, then `hold`, then `skip`.

doriath refuses to start if a mount, or a guarded path in a repository, goes through a symlink in a directory that the jail can write. An agent can put such a link there in an earlier session. Other symlinks, such as `~/.nix-profile`, mount their target.

A guarded path that is itself a symlink is an exception, because tools make such links. For example, git-hooks.nix links `.pre-commit-config.yaml` into the Nix store, and jj links `.jj/repo/config.toml` to your jj config. No mount can make a symlink read-only, so doriath guards the link in these ways:

- In a read-only mount, the link cannot change.
- In a writable mount, doriath records the target and watches the link. If the jail changes the link, doriath puts it back at once and sends a notification. It also reports the change at the end of the session and in `doriath status`.
- doriath refuses to start if the link points to a path that the jail can write.

doriath refuses `/`, the home directory and the directories above it, in all modes. It refuses writable mounts under `/nix/store`, `/usr`, `/bin`, `/lib` or `/opt`, because programs there get credentials by name.

## Path lists

`[paths]` holds lists that only restrict the agent. Each layer adds to them, and no layer can remove an entry. A change to them does not ask you to [allow the profile](#allowed-profiles) again, because they give the jail nothing.

The [modules in every profile](/reference/modules/#modules-in-every-profile) set these lists for your keys, your login, `/tmp` and the files that your machine runs in a repository.

An entry is an absolute path, a path under `~`, or a path under `{repository}`, without `..` or a trailing slash. A request matches an entry when it names the path, a folder above it, or a path inside it.

- `refuse`: doriath refuses a request for the path before it asks you, as it does for your keys.
- `warn`: a request still asks you, with the `reason` as a warning from doriath. You can allow it once only, and the request shows no profile lines to keep. With `read = true`, a request to read the path also warns.
- `hold`: doriath keeps the path read-only in each mount that shows it, and warns on a request for it as `warn` does. `missing` is required, and says what happens when the path does not exist in a writable mount:
    - `move`: doriath puts nothing there. If the agent creates the path, doriath moves it at once to `~/.local/state/doriath/moved/<session>/` and tells you. Without inotify, doriath moves it only at the start and the end of the session.
    - `hold`: doriath puts an empty file there, as for [mounts](#mounts), or an empty folder with `folder = true`. Use it only where the empty file or folder changes nothing for the tools on your machine, such as `{}` in a JSON file.
    - `skip`: the agent can create the path.

## Home

The home directory in the jail is an empty folder for each session, under `~/.cache/doriath/agents/<profile>/scratch/`. Only mounts and caches show through it, so tools in `~/.nix-profile` or `~/.local/bin` need a mount. doriath deletes the other files that the agent writes in the home when the session ends.

At the end, doriath also lists each folder there that holds more than 512 MB, such as `~/.cache/bazel-disk`. It prints the `[[caches]]` lines that keep the folder for later sessions.

## Edits

The agent can ask to change a file that is read-only in the jail, such as `.git/config` when git or jj cannot write it. It writes the whole new content to a file, and runs `doriath request edit PATH --reason TEXT < FILE`. doriath shows you what changes, and writes the change once if you allow it. The file stays read-only in the jail.

The `git` of the jail makes these requests itself, for the settings that git writes on its own. The upstream that `git push -u`, `git branch --set-upstream-to` or `git switch --track` records thus reaches `.git/config` as the safe list allows. `git remote add` asks you first.

An `edit` table on a read-only mount sets how doriath compares the file:

- `format = "git-config"` compares settings as git reads them, without following includes. Comments and layout are no change. doriath writes only the changed settings, never the file of the agent.
- `format = "text"` compares the whole file, and shows you a line diff. A read-only file without an `edit` table changes as text.

`safe` lists the settings that change without a question, as `KEY = VALUE`. In a key, `*` matches anything. In a value, `*` matches anything except `/` and `:`, and `**` matches anything. Any other change waits for your answer, and the request marks the settings that are not on the list. A text edit always waits.

`{git}` stands for each git directory that doriath guards, submodules included. A mount of `{git}/config` only adds an edit rule, because doriath keeps the file read-only already. The [`vcs-readwrite` module](/reference/modules/#vcs-readwrite) sets this rule:

```toml
[[mounts]]
path = "{git}/config"
edit = { format = "git-config", safe = [
  "branch.*.remote = *",
  "branch.*.merge = refs/heads/**",
] }
```

Thus upstream tracking changes at once. A setting that names a program, such as `core.fsmonitor`, the URL of a remote, or a remote that the config does not define, waits for you. jj workspaces need no setting: in the jail, git and jj record worktrees with absolute paths, which need no extension in `.git/config`.

## Repositories

With `[vcs] store = true`, each git or jj repository gets a writable store. The agent can commit, branch and add worktrees while your checkout stays read-only:

| Repository | Writable                                                                                                                                                    | Read-only                                                                                                                                                                             |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| git        | `.git` and its submodule stores, such as `objects`, `refs`, `HEAD`, `index`, `packed-refs` and their lock files                                             | `config`, `config.worktree`, `hooks`, `info`, `remotes`, `branches`, `commondir`, `objects/info/alternates`, `rr-cache`, existing packs, and each worktree's `commondir` and `gitdir` |
| jj         | `.jj/working_copy`, and in `.jj/repo` the `index`, `op_heads`, `op_store`, `submodule_store`, `workspace_store`, `store/extra` and `git_import_export.lock` | the rest of `.jj/repo`, such as `config.toml`, `config-id`, `store/git_target` and `store/type`, and jj's git store as above                                                          |

In the jail, git reads a global config that doriath builds from yours. It leaves out credentials, URL rewrites, remotes, includes, hooks and settings that run a program. doriath copies in the files that your config makes git read, such as the global ignore rules, attributes and commit template, by default from `~/.config/git`. Thus git and jj in the jail ignore the same files as on your machine.

In a linked git worktree or a secondary jj workspace, doriath mounts the store of the main repository. Because `.git/config` stays read-only, git in the jail warns that it cannot remove the upstream settings of a deleted branch. The agent changes them through [edits](#edits).

At the start, doriath records your branches and bookmarks, and copies the loose objects. Existing packs, which hold almost all history, stay read-only. Thus a `git gc` in the jail cannot remove the objects that your branches point to. It cannot remove old packs either, so each gc writes the whole history to one more pack. For this reason, the git config of the jail sets `gc.auto = 0` and `maintenance.auto = false`.

At the end, doriath does these steps:

- It checks that the content of each object that the agent wrote has the name of that object, and removes the objects that fail. In a new pack, it checks only the objects that the start did not have. If few objects are new, doriath keeps them as loose objects and removes the pack. A pack of the whole history, from a `git gc`, thus takes less than a second. A large pack of mostly new objects, such as one from a fetch, can take a minute. doriath shows a progress bar while it checks.
- It keeps the start value of each branch that the agent moved, as `refs/doriath/<session>/<branch>`.
- It removes new LFS objects whose content does not match their name, because your checkout takes file content from the object with that name.
- It repairs each worktree that the agent added. The `.git` file and `commondir` point to your repository again, and doriath removes a `config.worktree` that the agent added.
- It moves aside, to `NAME.doriath-<session>`, what the agent left in a store for git on your machine to act on: a rebase, cherry-pick or revert to continue, a new `rr-cache`, and a new submodule store.

If doriath stops before the end, for example because it was killed, it does these steps when the next session uses the repository, or at [`doriath clean`](/reference/commands/#doriath-clean). Each other session that starts names the sessions that wait.

Until the session ends, do not run git in an agent worktree, and do not continue a rebase that the agent started. `doriath restore SESSION [BRANCH...]` puts moved branches and bookmarks back. It never runs on its own, because doriath cannot tell the moves of the agent from your moves. [`doriath clean`](/reference/commands/#doriath-clean) removes old agent worktrees and backups.

## Approvals

[Answering requests](/guides/approvals/) tells which requests wait for you, and where you answer them. `host_wait` under [config.toml keys](#configtoml-keys) sets how long the agent waits.

The agent can ask to write a path, or to read a folder that the jail does not show. Such a folder must exist. doriath refuses these paths before it asks you:

- symlinks, and paths inside `.git` or `.jj`
- paths that the profile hides
- system paths, `/var/tmp` included
- paths outside what Landlock allowed at the start: the home directory, `/tmp` and the writable mounts
- the paths of the [`private-paths` module](/reference/modules/#private-paths): keys and logins such as `.ssh`, `.gnupg` and `.password-store`, the config of git and jj, and the nix and home-manager profiles under `.local/state`
- the configuration, state and cache of doriath, and the caches of the profile

doriath also refuses the paths on the profile's `refuse` lists. A request for a path on a `warn` or `hold` list asks you with a warning, and you can allow it once only. See [path lists](#path-lists).

A repository in a granted path keeps the read-only control files of a `write` mount. Containers that start after a grant can bind the path as writable.

The agent can also ask to use a module of the profile in another repository, with [`doriath request module`](/reference/commands/#doriath-request-module). The module's `{repository}` and `{current}` entries then apply to that repository. Only the module's own `write` entries and `[vcs] store` come along. All entries that keep a path read-only, hidden or held come along, from the profile and from every module.

## Links

The agent opens a link in your browser with `xdg-open`, `$BROWSER` or [`doriath request open`](/reference/commands/#doriath-request-open). doriath opens only `http` and `https` links without a user name or password. Each link meets the first `[[open]]` rule whose host and path match it. The rules of the profile come before the rules of its modules:

- `allow` opens the link at once.
- `approve`, the default for a link that no rule names, asks you first. The request shows the whole link, because your browser sends all of it to the site, where you are signed in.
- `deny` refuses the link.

A link to `localhost`, `127.0.0.1` or `::1` goes to a server in the jail. Before doriath opens it, doriath asks you to forward the port of the link until the session ends. It asks also when a rule allows the link, and a `deny` rule still refuses it. See [ports](/guides/approvals/#ports).

A sign-in in the jail often opens a link whose `redirect_uri` sends your browser back to a port on `localhost`, where the tool waits. Your browser runs on your machine, so doriath forwards that port into the jail for five minutes. It does this for a link that you allow, and for a rule with `forward_redirect = true`. The agent modules allow their own sign-in pages this way, so `/login` in Claude Code works without a question. The forge modules allow links to their sites, where the agent can already send data through the API of the forge. Sign-in, account, settings and app pages of a forge ask you first, because one click there can authorize an app, install an app or make a token. A rule matches the path that your browser sends, so `/x/../settings` meets the rules for `/settings`.

A path or a `file://` link opens the file with the app that your machine uses for that kind of file, such as a markdown file in your editor. doriath asks you each time, and opens a file only if the jail shows it, it is a regular file that is not executable, and its kind is one that apps show rather than run: `.md`, `.markdown`, `.txt`, `.log`, `.csv`, `.tsv`, `.json`, `.yaml`, `.yml`, `.toml`, `.html`, `.htm`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp` or `.svg`. A `.desktop` launcher or a `.jar`, for example, can run code on your machine. Other schemes, such as `mailto:` or `vscode://`, are refused, because the app behind each scheme decides what a link can do.

## Forwards

`[[forward]]` makes doriath listen on a port of your machine for the whole session, and relay each connection to a port in the jail. It is the forward that [`doriath request forward`](/reference/commands/#doriath-request-forward) asks for, but you give it in advance, so no request appears. Use it for a tool in the jail that serves a page you open often, such as a notebook or a local inbox:

```toml
[env]
set = { NOTEBOOK_PORT = "8888" }

[[forward]]
name = "Notebook"
port = 8888
```

Most tools pick a free port each time they start. Set the port in `[env]`, as above, so that the forward and the tool agree. `name` shows in `doriath status`.

`port` takes one number for the same port on both sides, or `"HOST:JAIL"` in the order of `podman -p`. An address in front of the port, a range or `/udp` are refused, because doriath listens only on `127.0.0.1` and relays TCP.

If the port on your machine is taken when the session starts, the session runs without that forward and shows a warning. If nothing listens on the port in the jail, a browser gets a page that says so, and doriath writes the error to the [audit log](/reference/commands/#doriath-log). A repository profile cannot add a forward, because programs on your machine would reach the jail through it.

## MCP servers

`[[mcp]]` lists the MCP servers of the profile, for each agent that doriath supports. Your own MCP servers stay outside the jail.

- A local server (`command`, optional `env`) runs in the jail, with its limits. The agent can read its `env`, so do not put secrets there.
- A remote server (`url`, https) goes through the proxy. With `secret`, the proxy adds the secret as a bearer token to requests for the path of `url` only, and the `[[http]]` rules for the host apply. Another server on the same host does not get the token. Without `secret`, doriath allows the host and does not change its traffic.

For a remote server, `approve` and `deny` hold or refuse tools by name or glob. `allow` with `default = "approve"` holds all tools except the listed ones. doriath reads the JSON-RPC body on the path of `url`. A tool in `deny` is refused on all paths of the host. A held call becomes a request such as "Call notion tool notion-create-pages", with its arguments. If doriath holds one call in a batch, it holds the batch.

If a server has a secret or holds, doriath intercepts its host. Traffic to the endpoint that calls no tool goes through. Other traffic waits for your answer, as on each host with a credential. This includes other paths, and bodies that doriath cannot read as JSON-RPC.

doriath cannot hold the tools of a local server, because the server talks to the agent where doriath cannot see the traffic. A module can give a server with its holds, and the profile adds the secret.

Each adapter gives the list to its agent in the format of that agent, such as `--mcp-config` for Claude Code or `mcp_servers` in the config of Codex. doriath also writes the list to `/run/doriath/mcp.json` in the common `mcpServers` format, for an agent without an adapter. For Claude Code, the `.mcp.json` of a repository also applies.

## Keyring secrets

A secret with `keyring = true` is an entry in the keyring of your desktop. On Linux, doriath uses the Secret Service, which KWallet, GNOME Keyring and KeePassXC provide. This keyring is not the kernel keyring that the jail refuses.

```toml
[secrets.forgejo]
keyring = true
```

doriath reads the entry when the session starts. If the entry is missing, doriath asks you for the value in a dialog of your desktop. It keeps your answer in the keyring, so the next session does not ask. The dialog does not need a terminal, so it also opens for a session that an editor or the approvals page starts.

On Linux, doriath opens the program in `SSH_ASKPASS`, such as `ksshaskpass` on KDE. If `SSH_ASKPASS` is not set, it opens `pinentry`, the dialog of GnuPG. Without a display, such as over SSH, doriath does not ask, and the session starts without the secret.

If you close the dialog, the session starts without the secret, and doriath does not open the dialog again on its own. Click **Try again** on the card of the secret to open it again. You can also store or replace a value on the host with this command:

```sh
doriath profiles login NAME
```

To replace one value, name the secret, such as `doriath profiles login my-app forgejo`. A script can give the value on standard input.

- If the keyring is locked, your desktop asks you to unlock it.
- doriath closes a dialog that gets no answer in 2 minutes.
- Each profile has its own entries, so two profiles can give different values to one secret name. An entry has the service `doriath` and the account `PROFILE/NAME`.
- If no keyring answers, the secret is unavailable. doriath does not read the value from a file or another source.
- doriath has no `file` source, so that no secret stays on your disk. A profile with `file` does not load. Use `keyring = true`, and store the value with `doriath profiles login PROFILE NAME` and standard input.
- A repository profile cannot use `keyring`, because the keyring holds your own values.

## OAuth logins

A secret with `oauth` is a login that doriath keeps on the host. To sign in, run this command on the host:

```sh
doriath profiles login NAME
```

The command signs in to each OAuth secret of the profile that has no login, or to the secret that you name. doriath opens the sign-in page in your browser, and gets the answer on the loopback address of the host, which the jail cannot reach.

- With `mcp`, doriath finds the sign-in server from the MCP server, and registers itself as a client.
- With `issuer`, doriath signs in as `client_id` with `scopes`.

The proxy adds a fresh access token to each request that uses the secret, so the agent never holds a token. In a session, doriath refuses the sign-in of the agent to a server that doriath has a login for, because the agent can read a token that it gets in the jail. The metadata of the server stays readable.

If the refresh token stops working, doriath tells you to run `doriath profiles login` again. Tokens are in `~/.local/state/doriath/oauth/<profile>/<name>.json`, with mode 600, outside the jail.

## Containers

`[podman] images` lists the images that containers can use. Each entry is a [`path.Match`](https://pkg.go.dev/path#Match) glob over a full reference, such as `docker.io/library/postgres:16`:

- Short names expand as in Docker.
- `*` does not match `/`.
- A pattern without a tag matches all tags.
- `["*"]` allows all images.

The `podman` module allows `docker.io/library/*`, `localhost/*`, the images of Playwright and the helpers of Testcontainers.

The first pull of a tag records its digest in `~/.local/state/doriath/images/<profile>.json`. If the tag later resolves to a different digest, doriath asks you before the pull. Containers of a pinned tag run the pinned digest. To trust a tag again, delete its line.

Containers can bind only what the profile mounts, with the same limits. doriath refuses privileged containers, added capabilities, devices, host namespaces other than the network, and image pushes without your approval.

## config.toml keys

```toml
# notifications shows approvals as desktop notifications with buttons.
#
# tray shows an icon in the status area of the desktop while doriath web
# runs. A dot marks it while requests wait, and a click opens the page.
[desktop]
notifications = true
tray = true

[approvals]
# How long a held request waits for you before the agent gets an error.
# The default is 2m with desktop notifications and 0s without them.
# The maximum is 1h.
host_wait = "2m"
# How long a permission prompt of the agent waits for you before the agent
# shows its own. The maximum is 1h.
tool_wait = "60s"

# title shows "doriath · PROFILE" as the window title while a session runs
# in a terminal, so that tabs and panes tell sessions apart. The old title
# comes back when the session ends.
#
# bar shows the session on the last row of your terminal, below the agent,
# with the profile, the session name, the hosts and the requests that wait
# for you. The agent gets one row less. With bar = false, the agent gets
# your terminal as it is.
#
# env sets variables on bubblewrap, the process your terminal sees in place
# of the agent. {command} is the name of the command doriath runs, such as
# claude. The jail does not get these variables, but do not put secrets in
# them. It is empty by default. To let an agent manager such as herdr find
# the agent, see the agent managers section of Looking inside a session.
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
| `~/.local/state/doriath/moved/<session>/` | What the agent created at a held path, which doriath moved out of the repository                      |
| `~/.cache/doriath/agents/<profile>/`      | The caches, `/tmp`, home, agent state and container storage of the profile                            |
| `$XDG_RUNTIME_DIR/doriath/sessions/<id>/` | Sockets and generated files of a running session                                                      |
