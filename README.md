# Girdle of Melian

girdle runs a coding agent, such as Claude Code, in a jail on a Linux host, such as a workstation or a server. The jail has its own files, network and processes. A proxy outside the jail decides which hosts the agent reaches and adds credentials to requests.

```sh
cd ~/Development/my-project
girdle run -- claude
```

Pre-alpha. Linux only.

```mermaid
flowchart LR
    subgraph jail["Jail: its own files, network and processes"]
        tech["Linux: bubblewrap, seccomp, Landlock<br/>macOS: Seatbelt, not supported yet"]
        agent["Agent<br/>(Claude Code, scripts, browsers)"]
        clone[("Private clone<br/>of your repository")]
        agent --> clone
    end

    proxy["girdle's proxy, outside the jail<br/>allowlist, request rules,<br/>TLS with a per-session CA"]

    secrets[("Your secrets")]
    you(["You"])
    internet(("Internet"))

    agent -- "every request" --> proxy
    proxy -- "allowed hosts,<br/>token added" --> internet
    proxy -. "requests a rule holds<br/>wait for approval" .-> you
    secrets --> proxy

    style tech fill:none,stroke-dasharray:3 3
```

## What girdle is for

girdle is for running coding agents on a host that you work on, with that host's tools, repositories and logins, without approving each step of the agent's work.

By design, girdle isolates less than sandboxes such as [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell), which run the agent in a container or a virtual machine with only its own image. girdle shares the host's toolchain, checkouts and kernel with the agent, so that the agent can work like you do.

girdle protects you from an agent that does something you did not ask for, for example after a prompt injection in a web page, an issue or a dependency. In a girdle session, the agent cannot:

- read your home directory, your other projects, your SSH keys or your tokens.
- read the credentials that girdle adds to its requests.
- reach a host that the profile does not name, your local network or a cloud metadata service.
- change files that run outside the jail, such as git hooks. The agent works on a clone of the repository.
- make a request that a rule holds for approval, until you approve it. The rules come from the profile and its modules. For example, the `github` module holds merges, releases and pushes.
- approve its own requests.

girdle does not protect you from:

- an agent that sends the project to a host that the profile allows. Allow only the hosts that the task needs.
- operations that an allowed program, such as `gh`, can do under the rules, for example a comment on GitHub.
- a bug in the Linux kernel. The jail shares the kernel with the host.

[Security limits](docs/security-limits.md) gives the full list and the reasons.

## How it works

| Part            | What it does                                                                                                                                                                                                                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Files           | bubblewrap mounts the system read-only. The home directory, `/run`, `/tmp`, `/var` and `/opt` are empty. The paths that the profile names are mounted at the same paths. A repository is mounted as a git clone, and its branches come back to your repository as refs under `refs/girdle/`. |
| Kernel          | seccomp refuses namespaces, mounts, `ptrace`, `bpf`, `io_uring`, kernel modules and terminal input injection. Landlock limits writes to the writable mounts.                                                                                                                                 |
| Network         | The jail has only a loopback interface. Programs reach other hosts through the proxy, with `HTTPS_PROXY`. The proxy allows the hosts that the profile names and refuses other hosts, private addresses and metadata addresses. Each decision goes to an audit log.                           |
| Credentials     | For a host with an `[[http]]` entry, the proxy terminates TLS with a per-session CA, adds the credential to requests from the programs that the profile names, and applies the request rules: allow, approve or deny.                                                                        |
| Approvals       | A request that a rule holds waits until you allow or deny it in a desktop notification or with `girdle approvals`, for example over SSH on a server. Claude Code's permission prompts use the same queue.                                                                                    |
| Commit signing  | An SSH agent with an agent-only key signs git commits. It refuses other uses of the key.                                                                                                                                                                                                     |
| Containers      | A podman service runs in a separate user namespace and shares the jail's network. A broker checks each API call: mounts, privileges, images.                                                                                                                                                 |
| Resource limits | Each session runs in a systemd user scope with a task limit and a memory limit.                                                                                                                                                                                                              |
| Looking inside  | `girdle exec` runs a command in a running session. `girdle forward` makes a port in the jail reachable on the host's localhost.                                                                                                                                                              |

girdle is one static Go binary that bundles bubblewrap. It needs a Linux kernel with unprivileged user namespaces, and podman for containers.

## Docs

- [Install](docs/install.md)
- [Configuration](docs/configuration.md)
- [Security limits](docs/security-limits.md)
- [Engineering principles](docs/engineering.md)
