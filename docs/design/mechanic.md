# Design: the host profile

Status: proposal. No code yet. The profile is called `host` here, so that a rename is one search and replace. The plan that this design follows, `~/Documents/Context/credentials-and-agents/plan-yubikeys-and-mechanic-2026-11-21.md`, does not exist on this machine, so the decisions below come from the request: reading is free, each change to the system waits for your approval, there is no root, and SSH to a new host waits for approval.

The `host` profile lets an agent debug your machine: kernel filesystems, systemd, logs, networking, remote hosts and old agent sessions. It replaces running an agent without a jail.

## Principles

- Reading costs no approval. A read can still leak, so what the agent reads must not hold secrets, or must be filtered.
- A call that changes the system waits on the [approvals page](/guides/approvals/). The agent sees the hold, not a refusal.
- No root. When a fix needs `sudo`, the agent prints the command for you to run.
- Each capability is a module with a narrow default, as the engineering rules ask. A profile that does not list the module does not get it.
- doriath keeps no secret on disk. Nothing here writes one.

## 1. Host processes

**Today.** The jail has its own PID namespace (`--unshare-pid`) and a fresh `/proc`. The agent sees only its own processes. `ps`, `top` and `pgrep` show nothing about the host.

**Change.** The agent must see which services and processes run, with their command lines, state and open ports.

**Threat.** A process list holds secrets. Other processes' `/proc/PID/cmdline` and `environ` can carry tokens, and a password manager or browser can show a lot in `cmdline`. `environ` of your own processes is readable by the same user. Sharing the host PID namespace would also let the agent send signals to your processes and read their memory through `ptrace`, unless the kernel's Yama setting and the seccomp filter stop it.

**Options.**

1. Share the host PID namespace, and mount `/proc` with `hidepid=2`. `hidepid` hides other users' processes, not your own, so it does nothing here: all of the processes belong to you.
2. A read-only `/proc` view built by a broker. doriath reads `/proc` on the host and answers a fixed set of queries: process list (pid, parent, user, state, start time, executable path), the command line with values of known secret flags and environment-looking arguments removed, and listening sockets. The jail gets a command, `doriath host ps`, and a fake `/proc` is not offered.
3. A host-PID jail with seccomp that denies `ptrace`, `process_vm_readv`, `kill` and `/proc/*/environ`, `/proc/*/mem` reads. Reads of `cmdline` remain.

**Recommendation.** Option 2, first with `ps`-like output and `ss`-like output, and without `environ`. It adds no kernel access, and the broker is where redaction lives. Option 3 is a later step if the agent needs `strace`-like tools, and it needs a threat review of its own.

## 2. systemd and the journal

**Today.** The jail shares no D-Bus socket. `DBUS_SESSION_BUS_ADDRESS` is not passed (`envrisk.go` lists it as a risky variable). `/` is read-only, so `/run/systemd` files are readable but `systemctl` cannot reach a bus. The journal files in `/var/log/journal` and `/run/log/journal` are readable only for the group `systemd-journal`, and the jail runs as your user without that group.

**Change.** `systemctl status`, `list-units`, `show`, `journalctl` and `systemd-analyze` work. `restart`, `start`, `stop`, `enable` and `daemon-reload` wait for your approval.

**Threat.** The system bus is a root-equivalent surface: `StartTransientUnit` runs any command as root, and polkit decisions depend on the caller's session. The user bus can run a command as you outside the jail (`StartTransientUnit` on `systemd --user`), which escapes the jail completely. So the bus must never be exposed unfiltered.

**Design.** A D-Bus filter in front of each bus, with the system bus and the user bus as separate sockets.

- Use `xdg-dbus-proxy` first. It filters by name and by interface or method (`--call=org.freedesktop.systemd1=org.freedesktop.systemd1.Manager.GetUnit@/org/freedesktop/systemd1`). It can allow reads, but it can only allow or deny a call, it cannot hold one for approval.
- For holds, doriath needs its own broker that speaks the D-Bus wire protocol for one method set. A small Go broker with `godbus` parses each method call. A read method (`GetUnit`, `ListUnits`, `Get` on properties, `GetAll`, the `org.freedesktop.DBus.Introspectable` calls) passes. A write method (`StartUnit`, `StopUnit`, `RestartUnit`, `ReloadUnit`, `EnableUnitFiles`, `DisableUnitFiles`, `Reload`) becomes an approval request with the method, the unit and the mode. A method that the broker does not know is refused. `StartTransientUnit`, `SetProperties`, `Exec`-like calls and anything on `org.freedesktop.login1` that powers off are refused outright, not held, because an approval card cannot show their risk.
- **Approval mid-call.** The broker keeps the method call open and does not answer it until you decide. D-Bus calls have a default timeout of 25 seconds, so the broker sends no reply early. systemctl waits up to 25 seconds, then it fails on its own timeout. The agent can run `doriath request wait ID` as with other held requests, and the hold lasts for the approval TTL, 10 minutes. So the card must say what the agent will do next ("run the command again after you allow it"), and an allow for `once` lets one call pass. This matches the host and path holds of the proxy.
- The approval card names the bus, the unit, the method and the job mode. "Allow for the session" is not offered for `Restart` and `Stop` of a unit that is in a list of units that the profile marks as critical (for example `NetworkManager.service`, `sshd.service`).
- **Journal.** `journalctl` reads the journal files directly, so the jail needs read access to `/var/log/journal` and `/run/log/journal`, and the group. The jail uses a user namespace, and bubblewrap cannot keep a supplementary group inside it. Two ways: (a) add your user to `systemd-journal` on the host (the profile cannot do it, and it widens the access of every program that you run), or (b) the broker runs `journalctl` on the host as you, with the group, and returns the text, so the jail holds no journal files. Option (b) can filter lines with the same secret patterns that your scanner uses. **Recommendation:** (b), with `doriath host journal` taking `journalctl` arguments from an allowlist (`-u`, `-b`, `--since`, `--until`, `-p`, `-g`, `-n`, `-o`, `--no-pager`). The user bus has its own journal files, which (b) covers too.

**Smallest start.** The broker, a read-only method set, and the journal command. Writes come in a later commit.

## 3. SSH to other hosts

**Today.** The jail has no network namespace of its own beyond what the proxy gives: all egress goes through the HTTP proxy. Git over SSH works because the `github` and other forge modules have an `ssh` setting that carries SSH over HTTPS. A raw TCP connection is possible only through `[egress] tcp_ports` or `doriath request connect`, which reach the loopback address of your machine, not other hosts. No SSH agent for login exists: the `sshagent` package serves one key that signs only SSHSIG messages, so it cannot log in anywhere.

**Change.** `ssh host` and `scp` reach a host after you approve that host.

**Threat.** A login on a remote host is a new identity for the agent. The key that signs in decides what the agent can do there, and a key in your ssh-agent opens every host that trusts it. An agent that can log in anywhere can move data out, and it can read the `known_hosts` and `config` that name your hosts.

**Design.**

- **Egress.** Add a TCP egress type `[[ssh]] host = "NAME" port = 22` for approved hosts. The proxy accepts `CONNECT host:22` from the jail, as for HTTPS, and holds it for approval when the host is new (kind `ssh`, with the resolved address in the card). A tunnel for a host that you approved lasts for the session, and "allow always" writes nothing: doriath prints the profile lines, as it does for other grants. The proxy applies the existing address checks (no loopback, no link-local, no unnamed private addresses) unless the profile lists the host as local, because a LAN host is the normal case for this profile.
- **`ProxyCommand`.** The jail's ssh config sets `ProxyCommand doriath __connect %h %p`, so that `ssh` needs no argument. The jail reads no `~/.ssh` (hidden by `private-paths`), and doriath writes the ssh config into the session directory.
- **Host keys.** The jail needs `known_hosts`. Options: an empty file with `StrictHostKeyChecking=ask`, where ssh asks the agent's terminal, or a copy of your `known_hosts` that is read-only. A copy shows your host names to the agent. **Recommendation:** a read-only copy limited to hosts that you approved: when you approve a host, doriath adds its lines from your `known_hosts` if they exist, and the first connection to a host without a line is a second hold ("trust this host key: SHA256:...").
- **Which key.** Options:
    1. Forward a filtered ssh-agent socket that holds your keys and asks for approval for each signature. This reuses your YubiKey, and the card can show the host and the key. The cost is a card for every signature, and ssh makes several for a session with multiplexing off. A `ControlMaster` in the jail reduces it to one for each host.
    2. An agent-only key: doriath makes a key for the `host` profile, you add its public key to the hosts, and the key lives in the keyring, as the signing key does. Nothing asks for a signature, and your own key is never in reach.

    **Recommendation:** option 2 as the default, because it keeps your identity out of the jail, it needs no card per signature, and a revoked key affects only the agent. Option 1 as a later opt-in, `[ssh] agent = "approve"`, for hosts where only your key works. For option 1, the filter is the `sshagent` package extended: it passes `SSH2_AGENTC_SIGN_REQUEST` after a hold that names the host. The agent sees which host from the session data in the request, which is only known after the key exchange, so the card names the key and the session ID that the tunnel carries, and the proxy links them to the host of the tunnel that it approved.

**Smallest start.** The tunnel hold and the agent-only key, with `known_hosts` limited to approved hosts.

## 4. Kernel filesystems

**Today.** `/` is bound read-only, so `/sys`, `/proc/sys` and `/etc` are readable in the jail as the host shows them. `--proc /proc` mounts a new `/proc` that shows the jail's PID namespace. `--dev /dev` gives a minimal `/dev` (null, zero, full, random, urandom, tty, pts, shm). `devices = ["/dev/tpmrm0"]` binds a device node. Writes to `/sys` and `/proc/sys` fail, because the mounts are read-only and the user has no rights anyway.

**Missing.**

- `/proc` shows the jail's processes only. `/proc/net`, `/proc/sys/net` and `/proc/mounts` show the jail's namespaces, not the host's. `/sys/class/net` shows the jail's interfaces too, because the network namespace is separate. Hardware views (`/sys/class/*`, `/sys/devices`, `lspci`, `lsusb`) are right.
- `/dev` lacks device nodes for `lsblk`, `dmesg` and the DRM and input devices. `dmesg` reads `/dev/kmsg`, which the host may restrict by `kernel.dmesg_restrict`.
- `/sys/kernel/debug` and `/sys/kernel/tracing` need root.

**Design.** Reading `/sys` and `/proc/sys` needs no change. Host-namespace views go through the broker of section 1 (mounts, sockets, routes), because the jail cannot have both a fresh PID namespace and the host's `/proc`. `dmesg` goes through the journal command (`journalctl -k`). A `devices` list lets the profile name `/dev/dri/*` or `/dev/input/*` read-only. Nothing here writes: `/proc/sys` and `/sys` stay read-only mounts, and a write request is a section 2 hold if it goes through a unit (`systemd-sysctl`, `modprobe`), or a command for you to run.

## 5. Wider home read access

**Today.** The jail mounts only what a profile names. `~/.config`, `~/.local/share` and `~/.local/state` are not visible. The built-in `private-paths` module makes requests for key and login paths refuse (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gh`, `~/.local/share/keyrings`, `~/.password-store`, and others).

**Change.** The agent can read most of your configuration to debug a setup, without the credential paths.

**Design.** Mounts nest, and a deeper path applies in its subtree, with the lowest privilege winning on one path. So:

```toml
[[mounts]]
path = "~/.config"

[[mounts]]
path = "~/.local/share"

[[mounts]]
path = "~/.local/state"

[[mounts]]
path = "~/.config/gh"
mode = "hide"
```

with one `hide` mount for each credential path. A hidden path shows as an empty directory or is not mounted, so the agent cannot tell a secret from nothing. The list is long and changes, so doriath must not keep a second copy by hand. Options: (a) a module `host-secrets` with a generated list, built from the file that you keep in `~/.home.nix/modules/cli/secret-scan/credential-paths.nix`, through your home-manager module, which writes `~/.config/doriath/modules/host-paths.toml` as a user module. A user module holds `[[mounts]]` entries, so this works with today's loader. (b) a `hide_from` setting that reads a plain list. **Recommendation:** (a), because nothing in doriath changes, and the single source stays in the nix repository. A test in your nix config can fail when a path in the scanner list is missing in the generated module.

Two further limits:

- `hide` covers the paths in the list. A secret in an unexpected place, such as a token in `~/.config/app/config.toml`, stays readable. Reading is "free" only up to this list. `doriath doctor` could warn when the `host` profile mounts a path that its secret scanner flags, if the scanner can run on demand (open question 3).
- The jail must not mount `~/.cache/doriath`, `~/.config/doriath` or `~/.local/state/doriath`: the `private-paths` rules and the repository profile limits already forbid it for a repository profile, and the `host` profile must hide them as well (one exception in section 6).

## 6. Past agent sessions

The request: search an earlier session, such as one about a VPN that did not connect.

**Today.** Transcripts live in `~/.claude/projects` on the host for sessions outside doriath. A session in doriath writes them to `~/.cache/doriath/agents/PROFILE/home/.claude/projects`, and copies them back to `~/.claude/projects` when it ends. So most of a profile's transcripts reach the host folder. No profile can read either.

**Threat.** A transcript holds whatever the tools printed: tokens from `env`, file contents, command output. Your scanner runs `trufflehog` over these paths for this reason. A session that reads another profile's transcripts reads secrets that the other profile's jail kept from the first. For example, a transcript of a profile with a deploy token can show the token if a command printed it. Reading transcripts therefore ties profiles together.

**Options.**

1. Mount `~/.claude/projects` and `~/.cache/doriath/agents/*/home/.claude/projects` read-only. It is simple. The agent sees all of it, secrets included, and the second path also shows the live session files of other running sessions.
2. A filtered copy: a job on the host (or at session start) copies the transcripts through the secret patterns, replaces matches with `[redacted]`, and the jail mounts the copy. Staleness is a cost, and the redaction can miss a secret.
3. A search broker: `doriath host sessions search QUERY --since 7d` runs on the host, searches the transcripts, and returns matching snippets, with the same redaction as option 2, and the project and date. The agent never gets whole files unless it asks for one session by ID, and that is held for approval.

**Recommendation.** Option 3. It gives the use case ("find the VPN session") with the least exposure, and the redaction runs on the way out. Option 1 for `~/.claude/projects` only, as a later opt-in for a profile that you trust, if the broker is too slow. Never mount the cache folders of other profiles whole, and let the broker skip the transcripts of a profile that its own profile marks private.

## 7. VPN and network debugging

**Today.** The jail has its own network namespace. `ip addr`, `ip route`, `ss`, `resolvectl` and `nmcli` show the jail's empty network, not yours. NetworkManager and `wg` need the system bus, or root.

**Change.** The agent must see interfaces, routes, DNS state, listening sockets, NetworkManager connections and WireGuard peers, read-only.

**Threat.** The state names your hosts and peers. WireGuard output shows public keys and endpoints, and private keys only for root (`wg showconf` needs root, `wg show` omits private keys). NetworkManager settings can hold a secret (Wi-Fi passwords, VPN secrets), which `nmcli connection show` prints only for a user with the right agent or with `--show-secrets`.

**Options.**

1. Share the host network namespace. The jail then needs no broker for `ip` and `ss`, but it also skips the proxy: nothing inspects egress. This breaks the central rule of doriath (all egress goes through the proxy) and is refused.
2. A broker for a fixed set of commands run on the host as you: `ip -j addr|route|rule|link`, `ss -tulpn` (the process column is redacted by section 1 rules), `resolvectl status`, `wg show` (without `--show-secrets`, which does not exist), `nmcli -t -f ... connection show` with the secret fields not requested. Output goes back as text.
3. D-Bus read access to `org.freedesktop.NetworkManager` through the section 2 broker, with `GetSettings` refused (it returns secrets for some connection types) and `GetAllDevices`, `ActiveConnections`, `State` and property reads allowed.

**Recommendation.** Options 2 and 3 together. Option 2 is the first commit: it covers `ip`, `ss`, `resolvectl` and `wg`. Option 3 follows the D-Bus broker. A VPN debug session needs `journalctl -u NetworkManager` and the `wg` state, so sections 2 and 7 together cover the Proton VPN case. Changes (`nmcli connection up`, `wg-quick up`) are holds on the NetworkManager method `ActivateConnection`, or commands for you to run when they need root.

## One broker, one channel

Sections 1, 2, 4, 6 and 7 share one design: a broker on the host answers a fixed set of read queries, redacts the output, and holds writes for approval. It reuses what exists: the control socket of a session, the approval manager, the audit log and the `request` command family. In the jail, `doriath host ps|journal|net|sessions|systemctl` are the front ends, and `systemctl`, `journalctl`, `ip` and `ss` can be shims that call them, so an agent's habits work. The broker runs as you on the host, so every query must be a closed set of arguments, not a shell line.

## Threats the profile adds

- **A broker bug is a host escape.** The broker takes agent input and runs host programs. It must not build a shell line, must use fixed argument lists, and needs fuzz tests with a security property, as the rules for parsers that see agent input require.
- **Redaction misses.** Pattern-based redaction is incomplete. The profile says so in its `description`, and the limits on the threat model page list it.
- **Held calls can be abused for fatigue.** Many restart cards teach you to click allow. The broker rate-limits cards per session and per unit, and the card for a critical unit never offers "for the session".
- **The profile as a whole is a high-trust profile.** It holds the first two rules of the shipped-modules list only partly: it reads more of your home. Say so in the module description, and on the threat model page.

## Implementation plan

Each step is one commit with tests, smallest useful first.

1. `feat(modules): add a host module with kernel filesystem reads`. A module and profile `host` with the `[[mounts]]` for `~/.config`, `~/.local/share` and `~/.local/state` and the hide list from section 5, plus a test that the credential paths are hidden. No broker yet. The doc update on the threat model page.
2. `feat(session): add a host broker with ps and network queries`. The broker, the `doriath host ps` and `doriath host net` commands with fixed command sets and redaction, an audit record, and fuzz tests. Covers sections 1 and 7 (option 2) and the `mounts`/`sockets` part of 4.
3. `feat(session): add journal reads through the broker`. `doriath host journal` with the argument allowlist and redaction. Shims for `journalctl` and `dmesg`.
4. `feat(session): add a filtered D-Bus read broker`. Read methods of systemd1 and NetworkManager, system and user buses, with refusal of unknown methods. Shim for `systemctl status|show|list-units`.
5. `feat(approval): hold systemd write methods`. The write method set, the card, the hold across the call, critical unit list, rate limits. Shim for `systemctl restart|start|stop`.
6. `feat(session): search past agent sessions through the broker`. `doriath host sessions` with redaction.
7. `feat(proxy): hold SSH to a new host`. The `ssh` egress type, the hold, the session `ssh` config and `known_hosts` for approved hosts.
8. `feat(sshagent): give the host profile its own key`. The agent-only key in the keyring and its use in the jail. The approving agent for your own key comes later and only if the open question below asks for it.
9. `docs: describe the host profile`. The guide page and the limits on the threat model page.

## Open questions

1. **Journal access.** Is it acceptable for the broker to read the journal as you, with the group `systemd-journal` added on the host? Without it, `journalctl` shows only your user journal.
2. **SSH key.** Should the profile get its own agent-only key (recommended), or must it use your YubiKey key with a card for each signature?
3. **Secret scanner.** Can doriath run your scanner on demand for the redaction patterns and for `doctor`, or should doriath ship its own pattern list?
4. **Transcripts.** Is the search broker enough for past sessions, or do you want the read-only mount of `~/.claude/projects` as well?
