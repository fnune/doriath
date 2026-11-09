These steps are for an agent that helps a person write a doriath profile for a project. A profile decides what the jail allows, so the person approves each file before you write it.

## Rules for the agent

- If the variable `DORIATH_BROKER` is set, you run in a jail. Follow "Draft in a jail" below.
- Show the full content of each file before you write it. Write it only after the person says yes.
- Write only three kinds of files: the profile, the line in the project's `.envrc`, and the doriath part of a home-manager configuration.
- Do not read, print or store a secret value. Write only the command or the file that gives the secret.
- Do not create keys or tokens. Give the person the command or the page.
- Do not run `doriath run`, and never with `--learn`. Learning mode reaches every public host, so the person starts it.

## Draft in a jail

In a jail, the doriath configuration is not visible, and `doriath doctor` checks the jail instead of the host. You can still read the project and draft the profile:

1. Write the draft to a scratch folder, such as `$TMPDIR/doriath/profiles/NAME.toml`.
2. Check it with `DORIATH_CONFIG_DIR=$TMPDIR/doriath doriath profiles show NAME`.
3. Ask the person where the profile goes. If the jail does not show that folder, ask for it with `doriath request write PATH --reason TEXT`, or let the person save the file.
4. Give the person the checks to run on the host: `doriath profiles show NAME`, `doriath doctor --profile NAME` in the project, and the steps of the last section.

## Find how the person installs doriath

Run `doriath doctor`. If it fails, show the person its output, and stop until the machine passes.

Then find where profiles live:

1. Run `ls -la ~/.config/doriath/profiles`.
2. If the profile files are links into `/nix/store`, home-manager writes them. Ask the person for the path of the home-manager configuration, and find `programs.doriath` in it.
3. If a link points to a folder, such as `private -> ~/Development/doriath-profiles`, the person keeps those profiles in a repository. Ask whether the new profile goes there.
4. Otherwise, the profile is a TOML file at `~/.config/doriath/profiles/NAME.toml`.

A profile for one project can also live in the project, at `.doriath/NAME.toml`. Sessions name it `repo:NAME`, and everyone who works on the project gets it. Put only what the project needs there: modules, hosts, mounts and caches. Keep secrets, signing keys and personal folders in a profile of the person's own, and compose the two, such as `my-app+repo:dev`. `.doriath` must be a folder in the repository, not a link. Ask the person where the profile goes. See https://doriath.fnune.com/reference/configuration/#repository-profiles.

Run `doriath profiles list`. If a profile already covers part of the work, ask whether to compose with it, such as `--profile my-app+deploy`, instead of a copy. See https://doriath.fnune.com/reference/configuration/#composed-profiles.

## Choose the modules

A profile lists modules. Each module holds the hosts, caches and rules of one tool. Run `doriath modules list` for the modules on this machine, and `doriath modules show NAME` to read one. Start from these:

- `vcs-readwrite` for a git or jj repository, so that the agent edits and commits in it. Use `vcs-readonly` instead if the agent must only read the checkout and work in worktrees.
- `docs`, so that the agent can read documentation sites.
- One agent module: `claude`, `codex`, `gemini` or `opencode`. Ask the person which agent they use.

Read the files of the project to find the toolchains:

| File in the project                            | Module       |
| ---------------------------------------------- | ------------ |
| `go.mod`                                       | `go`         |
| `package.json`, a lockfile of npm or pnpm      | `node`       |
| a Playwright config                            | `playwright` |
| `.pre-commit-config.yaml`                      | `pre-commit` |
| `flake.nix`, `shell.nix`                       | `nix`        |
| a `Dockerfile`, `compose.yaml`, Testcontainers | `podman`     |
| a `pom.xml`                                    | `maven`      |

Some builds need settings instead of a module:

- If the tests start their own sandboxes, such as bubblewrap or a nested doriath, add `[hardening] namespaces = true`.
- If containers use images outside `docker.io/library`, add them to `[podman] images`, such as `"ghcr.io/acme/*"`.

Run `git remote -v` to find the forge, and add `github`, `gitlab`, `forgejo` or `bitbucket` for it. Without a forge module, the agent can read public pages of the forge, but it cannot push or open pull requests. `nix-daemon` and `aws` give the jail more reach. Add them only if the person asks for them.

## Choose the mounts

The jail shows the folder where the session starts. `vcs-readwrite` makes the whole repository writable, except files that the machine runs on its own, such as `.envrc`. `vcs-readonly` keeps the repository read-only.

For sessions side by side, the agent works in worktrees. The `claude` module makes `.claude/worktrees` writable. Ask the person where they keep worktrees, and mount that folder with `mode = "write"`. If the folder holds worktrees of other projects, mount a narrower folder, because a large writable folder is slow to walk.

The jail shows nothing of the home that the profile does not name. Run `command -v` for the tools of the project. If they are under the home, such as `~/.nix-profile/bin`, mount that folder read-only. For Nix, also mount `~/.local/state/nix` and `~/.local/state/home-manager` with `missing = "skip"`, because the profile links through them.

Do not make a path writable if the machine runs files from it on its own, such as shell startup files, `~/.local/bin`, git hooks or `.envrc`. Code that the agent writes there runs outside the jail at the next login or commit. See https://doriath.fnune.com/threat-model/#profiles.

Hide files with secrets that the agent does not need, such as `.env` files. Git ignores most of them, so look in the ignored files with `git ls-files --others --ignored --exclude-standard --directory`. Add a mount with `mode = "hide"` for each one.

## Add credentials

Each forge module needs a token in a secret with a fixed name, such as `github`. Tell the person to make a new token for this profile only, with the smallest scope that the work needs. https://doriath.fnune.com/forges/ gives the steps for each forge. A token of an organization can need an approval from its admins, so say this before the person starts.

Do not add a rule that allows every request to a host that gets a credential. The agent can then do all that the token permits.

Ask which password manager the person uses. `command -v rbw bw op secret-tool` shows the ones that are installed. These commands print a secret:

- `rbw`: `["rbw", "get", "ITEM"]`
- `bw`: `["sh", "-c", "bw get password ITEM --session \"$(bw unlock --raw)\""]`, which asks for the password one time for each session
- `op`: `["op", "read", "op://VAULT/ITEM/credential"]`
- `secret-tool`: `["secret-tool", "lookup", "KEY", "VALUE"]`
- the keyring of the desktop, without a command: `keyring = true`. The person stores the value with `doriath profiles login PROFILE`.
- a file with mode 600: `file = "~/.config/doriath/keys/NAME"`

Run `command -v` for the program of the command. If the path is a shim of a version manager, such as mise or asdf, use the absolute path of the real program. A shim selects its tool from a config in the working folder, and the agent can write that config.

Run `git config --get commit.gpgsign` and `jj config get signing.behavior`. If either one signs commits, the profile needs `[signing]`. Give the person the two choices:

- A signing key for the profile. The person creates it with `ssh-keygen -t ed25519 -N '' -f ~/.config/doriath/keys/NAME-signing`, and adds the public key to the forge as a signing key. The profile then has `[secrets.signing]` and `[signing] key = "signing"`.
- `[signing] enable = false`. The agent then commits unsigned.

A session starts without a secret that fails, and what needs the secret fails until the person fixes it. The signing key, and each secret with `required = true`, stop the session instead. Tell the person to create the secrets before the first session.

## Write the profile

This example is a TOML profile for a Go and Node project on GitHub, with Claude Code:

```toml
description = "My app"
modules = ["vcs-readwrite", "docs", "go", "node", "github", "claude"]

[secrets.github]
command = ["rbw", "get", "github-my-app"]

[[mounts]]
path = "~/Development/.worktrees/my-app"
mode = "write"

[[mounts]]
path = "{repository}/.env"
mode = "hide"
```

In home-manager, the same profile goes under `programs.doriath.profiles.my-app`, with the same keys as attributes. `packages` adds tools to the `PATH` of the jail. See https://doriath.fnune.com/guides/home-manager/#profiles-in-nix.

After you write a TOML profile, run `doriath profiles show NAME`. It shows an error for a profile that does not load, and it names the module behind each entry. Show the output to the person. For a home-manager profile, ask the person to run `home-manager switch` first.

In the project, run `doriath doctor --profile NAME`. It tells whether the jail shows the repository, and whether the agent can commit and sign there.

## Start sessions from the project

If the person uses direnv, add `use doriath NAME` to the project's `.envrc`, after `use flake`. For a composed profile, name each part, such as `use doriath my-app repo:dev`. If `git ls-files .envrc` shows that the repository tracks `.envrc`, put the line in `.envrc.local` instead, and keep that file out of the repository. The person then runs `direnv allow`. See https://doriath.fnune.com/guides/direnv/.

Without direnv, suggest an alias, such as `alias claude-my-app='doriath run --profile my-app -- claude'`.

## Give the rest to the person

End with a list of the steps that only the person can do:

1. Create the token and the secrets, then run `doriath doctor --secrets`.
2. Add the public signing key to the forge, if the profile has one.
3. Run a build in learning mode, such as `doriath run --profile NAME --learn -- make build`. At the end, doriath prints the `[egress]` lines to add to the profile.
4. Start the agent in a session, and allow the profile when doriath asks. doriath asks before the first session of each profile in each project, and again when the profile later gives more. A session without a terminal stops instead, and prints the `doriath profiles allow` command to run.
5. Sign in to the agent in the session. Each profile, and each composition, has its own agent login.
