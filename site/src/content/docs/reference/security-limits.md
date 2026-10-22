---
title: Security limits
description: What doriath leaves open, and why.
---

None of these lets an agent leave the jail, read your home directory or other projects, take a credential, change what runs outside the jail, or reach a host the profile does not name. What remains is narrower: an agent can send the mounted project to an allowed host, and do what an allowed program does under the rules and your approvals. Every sandbox that lets an agent do real work has this limit, so the blast radius comes from the profile: mount only the project, allow only the hosts the task needs, and keep secrets out of world-readable paths.

## Allowed hosts are a way out

A write to an allowed host can carry data out: a request to api.anthropic.com with the agent's own API key is valid, and the `github` module lets `gh` post comments. For a host without an `[[http]]` entry, doriath checks only the host and TLS server name. Behind a CDN that serves many sites, that name can front another site: the request inside the tunnel can name any host the CDN serves, and with Encrypted Client Hello so can the hidden server name. The shipped modules allow dozens of hosts, so the list is the boundary.

Why it stays: allowing writes allows exfiltration. Intercepting every host would make it visible, but the interceptor speaks only HTTP/1.1, which breaks gRPC clients such as Bazel's remote cache. The `claude` module already refuses requests that carry `x-api-key`. GitHub comments outside your repositories cannot be held: GraphQL names the repository by an opaque ID.

## The agent drives the programs it may use

Credentials and `[[egress.programs]]` hosts go only to named programs, which stops stray programs. It is hygiene, not a boundary: over TCP, doriath names the program that holds the socket when the connection opens, and a socket outlives the program that opened it, so a program can write its request and hand the socket to a named one before doriath looks. The agent can still run those programs with any arguments, steer them through config it can write, such as `~/.config/gh` in the jail, or preload a library into them. A program named by a writable path, such as Playwright's browser in its cache, can be replaced; doriath warns about each such path.

Why it stays: the agent needs these programs. Request rules and approvals control what they do. Pinning programs by hash for the session would close the replacement case and is not done yet.

## The host filesystem is readable

The jail sees `/etc`, `/nix/store`, `/usr`, `/sys` and other system paths read-only, under Unix permissions. Anything world-readable there, including secrets in the nix store, is readable by the agent.

Why it stays: agents use the host's toolchain, which reads widely. A read allowlist would break tools until each profile lists what they read.

## The kernel surface programs need

seccomp refuses namespaces, mounts, `ptrace`, `bpf`, `io_uring`, kernel modules, keyrings, terminal injection and rare socket families. It allows netlink beyond routing, nested seccomp filters, and `memfd_create`, which Chromium, .NET and `ss` need.

Why it stays: those tools break without them, and running a program from memory adds nothing while a file the agent writes runs as well.

## Same user, shared kernel

The jail runs as your UID, separated by user namespaces, seccomp and Landlock, so a kernel or bubblewrap bug lets the agent out as you. Container sandboxes make the same bet; only a virtual machine does better. The podman service runs as root in a subordinate user namespace without seccomp of its own, so a container runtime escape lands there, though the agent only reaches the broker in front of it. Base images a build pulls inside podman are not checked or pinned. doriath's init in the jail is non-dumpable, but the agent can signal it, which ends the session, or stop it, which holds new connections to the proxy until it continues and lets the agent choose when doriath names the program behind one.

Why it stays: files the agent writes belong to you, it uses your toolchain, and a session starts in under a second.

## Writable repositories

With the `vcs` module, the agent creates, moves and deletes branches and adds worktrees in your repository. doriath keeps the start value of every moved branch for `doriath restore`, keeps existing packs read-only, and at the end restores deleted or rewritten loose objects and removes new objects and packs git cannot verify, along with new bitmaps and commit graphs, which git rebuilds. Submodule stores get the same treatment. A worktree the agent adds has a `.git` file and an admin directory the agent can write, and git on your machine follows them, to another store's config and hooks, so `git status` there could run the agent's code. doriath watches them while the session runs: when one changes, it points both back at your repository, moves aside a `.git` directory put in their place, and removes a planted `config.worktree`, within milliseconds. It repeats this when the session ends, or at the next `doriath run` if doriath died, and reports what it changed; a worktree that claims to be outside the session's writable mounts, or reaches outside them through a symlink, is left alone and reported, and an admin directory the agent replaced with a symlink is removed. A `.git` directory the agent creates anywhere else in a write mount is a repository of its own, and git on your machine follows its config and hooks, like an `.envrc`. Review an agent worktree's files as you would a pull request. A `write` mount of a checkout is your checkout itself: git's and jj's control files are read-only, including those that did not exist, but `.envrc` and editor tasks are not.

Why it stays: worktrees are how agents work in parallel without touching your checkout, and a copy per session cost disk, time and a landing step.

## Trust that comes back to the host

- Claude's transcripts return to `~/.claude/projects`, so resuming one outside the jail reads agent-written history. They also go the other way: a session starts with the project's earlier transcripts, so the agent reads every earlier conversation about the project, including what you pasted into one outside the jail.
- Agent output reaches your terminal as it is; escape sequences can change its title or state.
- Caches and container storage are shared by a profile's sessions, so one can plant files a later one trusts. This is a gap to fix.

Why it stays: resuming sessions, seeing the agent's output and reusing build caches are features.

## Grants change mounts from the host

`doriath request write` and `doriath grant write` change the running jail's mounts through a helper with full capabilities over them. It runs doriath's own read-only binary and never follows symlinks. A request from the agent only makes writable what the jail already sees; `doriath grant write`, which you type on the host, can also attach a directory the jail does not see, and so exposes its contents for reading. A grant lasts until the session ends, because an open file outlives taking a mount back.

Why it stays: restarting for each writable path would lose the agent's work.

## Other trust

- `doriath run --learn` reaches every public host for that session. Use it for builds you start, not for agents.
- `doriath forward` listens on the host's loopback, which every local user reaches. On a shared server, that includes the other users.
- The `nix-daemon` module's builds run outside the jail, without the allowlist.
- A secret given as a command runs on the host with your environment, which trusts whoever wrote the profile.
- OAuth logins keep refresh tokens in doriath's state directory, readable by your user outside the jail, as your other logins are.
- Approvals rely on you. Tool requests carry text the agent wrote, and the notification says so; many requests in a row invite clicking allow. doriath refuses new ones while 32 are waiting, and shows the agent's other notifications 10 at once, then one a minute.
- Sessions get task and memory limits but no CPU quota by default; `[limits] cpu` sets one.
