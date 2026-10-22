package profile

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/secret"
)

const defaultApprovalTimeout = 60 * time.Second

// Loader reads profiles and the modules they name. Modules are looked up in
// order, so a user module shadows a built-in module of the same name.
type Loader struct {
	Profiles fs.FS
	Modules  []fs.FS
	Home     string
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

const maxProfileDepth = 8

// Names lists the profiles in the profiles folder and the folders inside
// it, such as a linked clone of a private repository. A profile is named
// after its file, so two files with one name are an error.
func (l *Loader) Names() ([]string, error) {
	files, err := l.files()
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(files)), nil
}

// File returns where the profile is, relative to the profiles folder, and
// false when no file defines it.
func (l *Loader) File(name string) (string, bool, error) {
	files, err := l.files()
	if err != nil {
		return "", false, err
	}
	file, ok := files[name]
	return file, ok, nil
}

func (l *Loader) files() (map[string]string, error) {
	files := map[string]string{}
	root, err := fs.Stat(l.Profiles, ".")
	if errors.Is(err, fs.ErrNotExist) {
		return files, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	if err := l.walk(".", []fs.FileInfo{root}, files); err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	return files, nil
}

func (l *Loader) walk(dir string, parents []fs.FileInfo, files map[string]string) error {
	entries, err := fs.ReadDir(l.Profiles, dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, pathCause(err))
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		file := path.Join(dir, e.Name())
		info, err := fs.Stat(l.Profiles, file)
		if err != nil {
			return fmt.Errorf("%s: %w", file, pathCause(err))
		}
		if info.IsDir() {
			if slices.ContainsFunc(parents, func(p fs.FileInfo) bool { return os.SameFile(p, info) }) {
				return fmt.Errorf("%s links back to a folder above it", file)
			}
			if len(parents) >= maxProfileDepth {
				return fmt.Errorf("%s: profiles nest more than %d folders deep", file, maxProfileDepth)
			}
			if err := l.walk(file, append(parents, info), files); err != nil {
				return err
			}
			continue
		}
		name, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok {
			continue
		}
		if other, taken := files[name]; taken {
			return fmt.Errorf("two files define profile %q: %s and %s; rename one", name, other, file)
		}
		files[name] = file
	}
	return nil
}

func pathCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func (l *Loader) Load(name string) (*Profile, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("profile name %q: use lowercase letters, digits and dashes", name)
	}
	file, ok, err := l.File(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		file = name + ".toml"
	}
	data, err := fs.ReadFile(l.Profiles, file)
	if err != nil {
		return nil, fmt.Errorf("read profile %q: %w", name, err)
	}
	top, err := decodeLayer("profile "+name, data)
	if err != nil {
		return nil, err
	}
	if top.Name != "" && top.Name != name {
		return nil, fmt.Errorf("profile %q: name field says %q", name, top.Name)
	}
	top.Name = name
	top.source = "profile"

	var layers []layer
	if err := l.collect(top.Modules, &layers, nil, map[string]bool{}); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	layers = append(layers, top)

	b := newBuilder(l.Home)
	for _, ly := range layers {
		b.apply(ly)
	}
	p, err := b.build(top)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return p, nil
}

func within(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func (l *Loader) collect(names []string, out *[]layer, stack []string, done map[string]bool) error {
	for _, name := range names {
		if slices.Contains(stack, name) {
			return fmt.Errorf("module cycle: %s -> %s", strings.Join(stack, " -> "), name)
		}
		if done[name] {
			continue
		}
		data, err := l.readModule(name)
		if err != nil {
			return err
		}
		ly, err := decodeLayer("module "+name, data)
		if err != nil {
			return err
		}
		if ly.Name != "" || len(ly.Secrets) > 0 {
			return fmt.Errorf("module %q: name and secrets belong in profiles", name)
		}
		if err := l.collect(ly.Modules, out, append(stack, name), done); err != nil {
			return err
		}
		done[name] = true
		ly.source = name
		*out = append(*out, ly)
	}
	return nil
}

// CheckModule reads a module and the modules it builds on, and reports the
// first one that does not decode.
func (l *Loader) CheckModule(name string) error {
	var layers []layer
	return l.collect([]string{name}, &layers, nil, map[string]bool{})
}

func (l *Loader) readModule(name string) ([]byte, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("module name %q: use lowercase letters, digits and dashes", name)
	}
	for _, src := range l.Modules {
		data, err := fs.ReadFile(src, path.Join(name+".toml"))
		if err == nil {
			return data, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("read module %q: %w", name, err)
		}
	}
	return nil, fmt.Errorf("module %q not found", name)
}

type builder struct {
	home     string
	deny     []string
	mounts   []mountLayer
	caches   []string
	devices  []string
	envSet   map[string]string
	envPass  []string
	envPath  []string
	programs []programsLayer
	allow    []string
	ports    []int
	tcp      []int
	http     []httpLayer
	signing  string
	unsigned bool
	podman   bool
	images   []string
	nix      bool
	vcsStore bool
	mcp      []mcpLayer
	harden   Hardening
	limits   Limits
	claude   claudeLayer
	disable  bool
	agent    agentLayer
	status   bool
	secrets  map[string]secretLayer
	modules  []string
	sources  map[string][]string
}

func newBuilder(home string) *builder {
	return &builder{home: home, envSet: map[string]string{}, secrets: map[string]secretLayer{}, sources: map[string][]string{}, limits: Limits{Tasks: DefaultTaskLimit, Memory: DefaultMemoryLimit}}
}

func (b *builder) from(source, key string) {
	b.sources[key] = appendNew(b.sources[key], source)
}

func (b *builder) apply(l layer) {
	if l.source != "profile" {
		b.modules = append(b.modules, l.source)
	}
	b.record(l)
	b.mounts = append(b.mounts, l.Mounts...)
	for _, m := range l.MCP {
		if i := slices.IndexFunc(b.mcp, func(x mcpLayer) bool { return x.Name == m.Name }); i >= 0 {
			b.mcp[i] = m
		} else {
			b.mcp = append(b.mcp, m)
		}
	}
	for _, c := range l.Caches {
		b.caches = appendNew(b.caches, c.Path)
	}
	for _, d := range l.Devices {
		b.devices = appendNew(b.devices, d)
	}
	for k, v := range l.Env.Set {
		b.envSet[k] = v
	}
	for _, k := range l.Env.Pass {
		b.envPass = appendNew(b.envPass, k)
	}
	for _, d := range l.Env.PathPrepend {
		b.envPath = appendNew(b.envPath, d)
	}
	for _, h := range l.Egress.Allow {
		b.allow = appendNew(b.allow, h)
	}
	for _, h := range l.Egress.Deny {
		b.deny = appendNew(b.deny, h)
	}
	b.programs = append(b.programs, l.Egress.Programs...)
	for _, p := range l.Egress.Ports {
		if !slices.Contains(b.ports, p) {
			b.ports = append(b.ports, p)
		}
	}
	for _, p := range l.Egress.TCPPorts {
		if !slices.Contains(b.tcp, p) {
			b.tcp = append(b.tcp, p)
		}
	}
	for _, h := range l.HTTP {
		b.mergeHTTP(h)
	}
	if l.Signing != nil {
		if l.Signing.Key != "" {
			b.signing = l.Signing.Key
		}
		if l.Signing.Enable != nil {
			b.unsigned = !*l.Signing.Enable
		}
	}
	if l.Podman != nil && l.Podman.Enabled != nil {
		b.podman = *l.Podman.Enabled
	}
	if l.Podman != nil {
		for _, img := range l.Podman.Images {
			b.images = appendNew(b.images, img)
		}
	}
	if l.Nix != nil && l.Nix.Daemon != nil {
		b.nix = *l.Nix.Daemon
	}
	if l.VCS != nil && l.VCS.Store != nil {
		b.vcsStore = *l.VCS.Store
	}
	if lim := l.Limits; lim != nil {
		if lim.Tasks != nil {
			b.limits.Tasks = *lim.Tasks
		}
		if lim.Memory != "" {
			b.limits.Memory = lim.Memory
		}
		if lim.CPU != "" {
			b.limits.CPU = lim.CPU
		}
	}
	if h := l.Hardening; h != nil {
		if h.Namespaces != nil {
			b.harden.Namespaces = *h.Namespaces
		}
		if h.Ptrace != nil {
			b.harden.Ptrace = *h.Ptrace
		}
		if h.Landlock != nil {
			b.harden.NoLandlock = !*h.Landlock
		}
	}
	if a := l.Agent; a != nil {
		if a.StatusLine != nil {
			b.status = *a.StatusLine
		}
		if a.ApprovalTimeout != "" {
			b.agent.ApprovalTimeout = a.ApprovalTimeout
		}
		for _, path := range a.Instructions {
			b.agent.Instructions = appendNew(b.agent.Instructions, path)
		}
	}
	if c := l.Claude; c != nil {
		if c.DisableConnectors != nil {
			b.disable = *c.DisableConnectors
		}
		for _, s := range c.DeniedMCPServers {
			b.claude.DeniedMCPServers = appendNew(b.claude.DeniedMCPServers, s)
		}
		for _, s := range c.Ask {
			b.claude.Ask = appendNew(b.claude.Ask, s)
		}
		for _, s := range c.Deny {
			b.claude.Deny = appendNew(b.claude.Deny, s)
		}
	}
	for k, v := range l.Secrets {
		b.secrets[k] = v
	}
}

func (b *builder) record(l layer) {
	for _, m := range l.Mounts {
		mode := m.Mode
		if mode == "" {
			mode = string(ModeRead)
		}
		b.from(l.source, "mount "+mode+" "+m.Path)
	}
	for _, c := range l.Caches {
		b.from(l.source, "cache "+c.Path)
	}
	for _, d := range l.Devices {
		b.from(l.source, "device "+d)
	}
	for _, h := range l.Egress.Allow {
		b.from(l.source, "host "+h)
	}
	for _, p := range l.Egress.Programs {
		for _, h := range p.Allow {
			b.from(l.source, "host "+h+" for "+strings.Join(p.Binaries, ", "))
		}
	}
	for _, h := range l.HTTP {
		b.from(l.source, "http "+h.Host)
	}
	for _, k := range l.Env.Pass {
		b.from(l.source, "env pass "+k)
	}
	for k := range l.Env.Set {
		b.from(l.source, "env set "+k)
	}
	for _, m := range l.MCP {
		b.from(l.source, "mcp "+m.Name)
	}
	if l.Podman != nil {
		for _, img := range l.Podman.Images {
			b.from(l.source, "image "+img)
		}
	}
	for k := range l.Secrets {
		b.from(l.source, "secret "+k)
	}
}

func (b *builder) mergeHTTP(h httpLayer) {
	i := slices.IndexFunc(b.http, func(x httpLayer) bool { return strings.EqualFold(x.Host, h.Host) })
	if i < 0 {
		b.http = append(b.http, h)
		return
	}
	cur := b.http[i]
	if h.Credential != nil {
		cur.Credential = h.Credential
	}
	if h.Default != "" {
		cur.Default = h.Default
	}
	for _, r := range h.Repositories {
		cur.Repositories = appendNew(cur.Repositories, r)
	}
	if h.SSH != nil {
		cur.SSH = h.SSH
	}
	cur.EncodedSlashes = cur.EncodedSlashes || h.EncodedSlashes
	cur.Rules = append(slices.Clone(h.Rules), cur.Rules...)
	b.http[i] = cur
}

func imagePattern(p string) error {
	if p == "*" {
		return nil
	}
	if _, err := path.Match(p, ""); err != nil {
		return fmt.Errorf("podman images %q: %w", p, err)
	}
	if !strings.Contains(p, "/") {
		return fmt.Errorf("podman images %q: name the registry, as in docker.io/library/postgres, or use \"*\" for any image", p)
	}
	return nil
}

func appendNew(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

var (
	headerName = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	limitValue = regexp.MustCompile(`^([0-9]+[KMGT]?|[0-9]{1,2}%|100%|infinity)$`)
	cpuValue   = regexp.MustCompile(`^[0-9]+%$`)
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (b *builder) build(top layer) (*Profile, error) {
	var errs []error
	p := &Profile{
		Name:            top.Name,
		Description:     top.Description,
		Env:             Env{Set: map[string]string{}},
		Podman:          b.podman,
		ContainerImages: b.images,
		NixDaemon:       b.nix,
		VCSStore:        b.vcsStore,
		Hardening:       b.harden,
		Limits:          b.limits,
		Secrets:         map[string]secret.Backend{},
		Modules:         b.modules,
		Sources:         b.sources,
	}
	for _, m := range b.mounts {
		if name, ok := strings.CutPrefix(m.Path, GitDir+"/"); ok {
			if err := addGitEdit(p, name, m); err != nil {
				errs = append(errs, fmt.Errorf("mount %s: %w", m.Path, err))
			}
			continue
		}
		path, placeholder := placeholderPath(m.Path)
		if !placeholder {
			var err error
			if path, err = b.expand(m.Path); err != nil {
				errs = append(errs, fmt.Errorf("mount: %w", err))
				continue
			}
			if err := CheckMount(path, b.home); err != nil {
				errs = append(errs, fmt.Errorf("mount %s: %w", m.Path, err))
				continue
			}
		}
		mode := Mode(m.Mode)
		if m.Mode == "" {
			mode = ModeRead
		}
		if mode != ModeRead && mode != ModeWrite && mode != ModeHide {
			errs = append(errs, fmt.Errorf("mount %s: mode %q: want read, write or hide", m.Path, m.Mode))
			continue
		}
		if err := checkMode(path, mode); err != nil {
			errs = append(errs, fmt.Errorf("mount %s: %w", m.Path, err))
			continue
		}
		e, err := buildEdit(m.Edit, mode)
		if err != nil {
			errs = append(errs, fmt.Errorf("mount %s: %w", m.Path, err))
			continue
		}
		p.Mounts = mergeKeepingLessAccess(p.Mounts, Mount{Path: path, Mode: mode, Optional: m.Optional, Edit: e})
	}
	for _, img := range b.images {
		if err := imagePattern(img); err != nil {
			errs = append(errs, err)
		}
	}
	for _, c := range b.caches {
		path, err := b.expand(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("cache: %w", err))
			continue
		}
		if !within(path, b.home) || path == b.home {
			errs = append(errs, fmt.Errorf("cache %s: must be inside the home directory", c))
			continue
		}
		p.Caches = append(p.Caches, Cache{Path: path})
	}
	for _, d := range b.devices {
		if !strings.HasPrefix(filepath.Clean(d), "/dev/") {
			errs = append(errs, fmt.Errorf("device %q: must be under /dev", d))
			continue
		}
		p.Devices = append(p.Devices, filepath.Clean(d))
	}
	for k, v := range b.envSet {
		if !envName.MatchString(k) {
			errs = append(errs, fmt.Errorf("env set %q: invalid variable name", k))
			continue
		}
		p.Env.Set[k] = v
	}
	for _, k := range b.envPass {
		if !envName.MatchString(k) {
			errs = append(errs, fmt.Errorf("env pass %q: invalid variable name", k))
			continue
		}
		p.Env.Pass = append(p.Env.Pass, k)
	}
	for _, raw := range b.envPath {
		d, err := b.expand(raw)
		if err != nil || !filepath.IsAbs(d) || strings.Contains(d, ":") {
			errs = append(errs, fmt.Errorf("env path_prepend %q: must be an absolute path without a colon", d))
			continue
		}
		p.Env.PathPrepend = append(p.Env.PathPrepend, filepath.Clean(d))
	}
	for _, m := range b.mcp {
		server, err := b.buildMCP(m)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p.MCP = append(p.MCP, server)
	}
	for _, h := range b.allow {
		pattern, err := ParseHostPattern(h)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress: %w", err))
			continue
		}
		p.Egress.Allow = append(p.Egress.Allow, pattern)
	}
	for _, h := range b.deny {
		pattern, err := ParseHostPattern(h)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress deny: %w", err))
			continue
		}
		p.Egress.Deny = append(p.Egress.Deny, pattern)
	}
	for _, prog := range b.programs {
		built, err := b.buildPrograms(prog)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress programs: %w", err))
			continue
		}
		p.Egress.Programs = append(p.Egress.Programs, built)
	}
	for _, port := range b.ports {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("egress port %d: out of range", port))
			continue
		}
		p.Egress.Ports = append(p.Egress.Ports, port)
	}
	for _, port := range b.tcp {
		switch {
		case port < 1 || port > 65535:
			errs = append(errs, fmt.Errorf("egress tcp port %d: out of range", port))
		case slices.Contains(p.Egress.Ports, port):
			errs = append(errs, fmt.Errorf("egress port %d: listed both as HTTP and as TCP", port))
		default:
			p.Egress.TCPPorts = append(p.Egress.TCPPorts, port)
		}
	}
	for _, h := range b.http {
		host, err := b.buildHTTP(h)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p.HTTP = append(p.HTTP, host)
	}
	for _, name := range slices.Sorted(maps.Keys(b.secrets)) {
		s := b.secrets[name]
		if !namePattern.MatchString(name) {
			errs = append(errs, fmt.Errorf("secret %q: use lowercase letters, digits and dashes", name))
			continue
		}
		backend := secret.Backend{File: s.File, Command: s.Command}
		if o := s.OAuth; o != nil {
			backend.OAuth = &secret.OAuth{MCP: o.MCP, Issuer: o.Issuer, ClientID: o.ClientID, Scopes: o.Scopes}
		}
		if s.File != "" {
			file, err := b.expand(s.File)
			if err != nil || !filepath.IsAbs(file) {
				errs = append(errs, fmt.Errorf("secret %q: file %q must be absolute or start with ~/", name, s.File))
				continue
			}
			backend.File = file
		}
		if err := backend.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("secret %q: %w", name, err))
			continue
		}
		p.Secrets[name] = backend
	}
	if b.unsigned && b.signing != "" {
		errs = append(errs, fmt.Errorf("signing: set key to sign commits, or enable = false to commit unsigned, not both"))
	}
	p.Unsigned = b.unsigned
	if b.signing != "" {
		if _, ok := p.Secrets[b.signing]; !ok {
			errs = append(errs, fmt.Errorf("signing key %q: add it under [secrets.%s] in the profile", b.signing, b.signing))
		}
		p.SigningKey = b.signing
	}
	for _, h := range p.HTTP {
		creds := []*Credential{h.Credential}
		for _, r := range h.Rules {
			creds = append(creds, r.Credential)
		}
		var missing []string
		for _, c := range creds {
			if c == nil || slices.Contains(missing, c.Secret) {
				continue
			}
			if _, ok := p.Secrets[c.Secret]; !ok {
				missing = append(missing, c.Secret)
				errs = append(errs, fmt.Errorf("http %s: secret %q: add it under [secrets.%s] in the profile", h.Host, c.Secret, c.Secret))
			}
		}
	}
	if b.limits.Tasks < 0 {
		errs = append(errs, fmt.Errorf("limits tasks %d: must be zero (no limit) or more", b.limits.Tasks))
	}
	if b.limits.Memory != "" && !limitValue.MatchString(b.limits.Memory) {
		errs = append(errs, fmt.Errorf("limits memory %q: want a size such as 8G, a share of the RAM such as 50%%, or infinity", b.limits.Memory))
	}
	if b.limits.CPU != "" && !cpuValue.MatchString(b.limits.CPU) {
		errs = append(errs, fmt.Errorf("limits cpu %q: want a percentage such as 200%%", b.limits.CPU))
	}
	agent, err := b.buildAgent()
	if err != nil {
		errs = append(errs, err)
	}
	p.Agent = agent
	p.Claude = b.buildClaude()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

func (b *builder) buildHTTP(h httpLayer) (HTTPHost, error) {
	host, err := ParseHostPattern(h.Host)
	if err != nil {
		return HTTPHost{}, fmt.Errorf("http: %w", err)
	}
	out := HTTPHost{Host: host, Default: ActionAllow, EncodedSlashes: h.EncodedSlashes}
	if h.Default != "" {
		action, err := parseAction(h.Default)
		if err != nil {
			return HTTPHost{}, fmt.Errorf("http %s default: %w", h.Host, err)
		}
		out.Default = action
	}
	if c := h.Credential; c != nil {
		cred, err := buildCredential(*c)
		if err != nil {
			return HTTPHost{}, fmt.Errorf("http %s credential: %w", h.Host, err)
		}
		out.Credential = &cred
		if h.Default == "" {
			out.Default = ActionApprove
		}
	}
	if ssh := h.SSH; ssh != nil {
		if strings.HasPrefix(h.Host, "*.") {
			return HTTPHost{}, fmt.Errorf("http %s ssh: name one host, not a pattern", h.Host)
		}
		remote := SSHRemote{User: ssh.User, Port: ssh.Port}
		if remote.User == "" {
			remote.User = "git"
		}
		if remote.Port == 0 {
			remote.Port = 22
		}
		if !namePattern.MatchString(remote.User) || remote.Port < 1 || remote.Port > 65535 {
			return HTTPHost{}, fmt.Errorf("http %s ssh: want a user such as git and a port from 1 to 65535", h.Host)
		}
		for _, name := range ssh.Hosts {
			if pattern, err := ParseHostPattern(name); err != nil || strings.HasPrefix(string(pattern), "*.") || strings.Contains(name, ":") {
				return HTTPHost{}, fmt.Errorf("http %s ssh hosts: %q is not a host name", h.Host, name)
			}
			remote.Hosts = append(remote.Hosts, name)
		}
		out.SSH = &remote
	}
	for _, r := range h.Repositories {
		pattern, err := ParsePathPattern(r)
		if err != nil {
			return HTTPHost{}, fmt.Errorf("http %s repositories: %w", h.Host, err)
		}
		if strings.Contains(r, "**") {
			return HTTPHost{}, fmt.Errorf("http %s repositories: %q: a repository prefix has a fixed number of segments, so it cannot hold **", h.Host, r)
		}
		out.Repositories = append(out.Repositories, pattern)
	}
	for _, r := range h.Rules {
		rule, err := buildRule(r)
		if err != nil {
			return HTTPHost{}, fmt.Errorf("http %s rule: %w", h.Host, err)
		}
		out.Rules = append(out.Rules, rule)
	}
	return out, nil
}

func buildCredential(c credentialLayer) (Credential, error) {
	if !namePattern.MatchString(c.Secret) {
		return Credential{}, fmt.Errorf("secret %q: use lowercase letters, digits and dashes", c.Secret)
	}
	scheme := Scheme(c.Scheme)
	if c.Scheme == "" {
		scheme = SchemeBearer
	}
	if c.Username != "" && scheme != SchemeBasic {
		return Credential{}, fmt.Errorf("username is only used with the basic scheme")
	}
	if c.Header != "" && scheme != SchemeHeader {
		return Credential{}, fmt.Errorf("header is only used with the header scheme")
	}
	switch scheme {
	case SchemeBearer, SchemeToken:
	case SchemeBasic:
		if c.Username == "" {
			return Credential{}, fmt.Errorf("the basic scheme needs a username")
		}
	case SchemeHeader:
		if !headerName.MatchString(c.Header) {
			return Credential{}, fmt.Errorf("the header scheme needs a header name, such as PRIVATE-TOKEN")
		}
	default:
		return Credential{}, fmt.Errorf("scheme %q: want bearer, token, basic or header", c.Scheme)
	}
	for _, b := range c.Binaries {
		if b == "" {
			return Credential{}, fmt.Errorf("binaries entries must not be empty")
		}
		if strings.Contains(b, "/") && !strings.HasPrefix(b, "/") {
			return Credential{}, fmt.Errorf("binary %q: a path must be absolute", b)
		}
	}
	return Credential{Secret: c.Secret, Scheme: scheme, Username: c.Username, Header: http.CanonicalHeaderKey(c.Header), Binaries: c.Binaries}, nil
}

var methodPattern = regexp.MustCompile(`^(\*|[A-Z]+)$`)

func buildRule(r ruleLayer) (Rule, error) {
	method := r.Method
	if method == "" {
		method = "*"
	}
	if !methodPattern.MatchString(method) {
		return Rule{}, fmt.Errorf("method %q: want an uppercase HTTP method or *", r.Method)
	}
	path, err := ParsePathPattern(r.Path)
	if err != nil {
		return Rule{}, err
	}
	action, err := parseAction(r.Action)
	if err != nil {
		return Rule{}, err
	}
	for _, b := range r.BodyContains {
		if b == "" {
			return Rule{}, fmt.Errorf("body_contains entries must not be empty")
		}
	}
	if r.Header != "" && !headerName.MatchString(r.Header) {
		return Rule{}, fmt.Errorf("header %q: want a header name such as x-api-key", r.Header)
	}
	if r.HeaderPrefix != "" && r.Header == "" {
		return Rule{}, fmt.Errorf("header_prefix needs header")
	}
	for _, g := range r.MCPTools {
		if !validGlob(g) {
			return Rule{}, fmt.Errorf("mcp_tools %q: want a tool name or a glob such as notion-create-*", g)
		}
	}
	rule := Rule{Method: method, Path: path, BodyContains: r.BodyContains, Header: http.CanonicalHeaderKey(r.Header), HeaderPrefix: r.HeaderPrefix, MCPTools: r.MCPTools, MCPNone: r.MCPNone, Action: action, Summary: r.Summary}
	if r.GraphQL != nil {
		g, err := buildGraphQL(*r.GraphQL)
		if err != nil {
			return Rule{}, err
		}
		rule.GraphQL = &g
	}
	if r.Credential != nil {
		cred, err := buildCredential(*r.Credential)
		if err != nil {
			return Rule{}, fmt.Errorf("credential: %w", err)
		}
		rule.Credential = &cred
	}
	return rule, nil
}

var graphQLName = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

func buildGraphQL(g graphQLLayer) (GraphQLRule, error) {
	op := GraphQLOperation(g.Operation)
	switch op {
	case GraphQLQuery, GraphQLMutation, GraphQLSubscription:
	default:
		return GraphQLRule{}, fmt.Errorf("graphql operation %q: want query, mutation or subscription", g.Operation)
	}
	out := GraphQLRule{Operation: op}
	if g.Fields == nil {
		return out, nil
	}
	if len(*g.Fields) == 0 {
		return GraphQLRule{}, fmt.Errorf("graphql fields: list at least one field, or leave fields out to match any")
	}
	for _, f := range *g.Fields {
		if !graphQLName.MatchString(f) {
			return GraphQLRule{}, fmt.Errorf("graphql field %q: want a GraphQL field name such as createPullRequest", f)
		}
	}
	out.Fields = slices.Clone(*g.Fields)
	return out, nil
}

func parseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case ActionAllow, ActionApprove, ActionDeny:
		return a, nil
	}
	return "", fmt.Errorf("action %q: want allow, approve or deny", s)
}

func (b *builder) buildAgent() (Agent, error) {
	a := Agent{StatusLine: b.status, ApprovalTimeout: defaultApprovalTimeout}
	if b.agent.ApprovalTimeout != "" {
		d, err := time.ParseDuration(b.agent.ApprovalTimeout)
		if err != nil || d <= 0 {
			return a, fmt.Errorf("agent approval_timeout %q: want a positive duration like 90s", b.agent.ApprovalTimeout)
		}
		a.ApprovalTimeout = d
	}
	for _, raw := range b.agent.Instructions {
		path, err := b.expand(raw)
		if err != nil {
			return a, fmt.Errorf("agent instructions: %w", err)
		}
		a.Instructions = appendNew(a.Instructions, path)
	}
	return a, nil
}

func (b *builder) buildClaude() Claude {
	return Claude{
		DisableConnectors: b.disable,
		DeniedMCPServers:  b.claude.DeniedMCPServers,
		Ask:               b.claude.Ask,
		Deny:              b.claude.Deny,
	}
}

func (b *builder) expand(p string) (string, error) {
	switch {
	case p == "~":
		p = b.home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(b.home, p[2:])
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q: must be absolute or start with ~/", p)
	}
	return filepath.Clean(p), nil
}

func (b *builder) buildPrograms(l programsLayer) (ProgramEgress, error) {
	if len(l.Binaries) == 0 || len(l.Allow) == 0 {
		return ProgramEgress{}, errors.New("each entry needs binaries and allow")
	}
	var out ProgramEgress
	for _, bin := range l.Binaries {
		if bin == "" {
			return ProgramEgress{}, errors.New("binaries entries must not be empty")
		}
		if strings.Contains(bin, "/") {
			expanded, err := b.expand(bin)
			if err != nil || !filepath.IsAbs(expanded) {
				return ProgramEgress{}, fmt.Errorf("binary %q: a path must be absolute or start with ~/", bin)
			}
			bin = expanded
		}
		out.Binaries = append(out.Binaries, bin)
	}
	for _, h := range l.Allow {
		pattern, err := ParseHostPattern(h)
		if err != nil {
			return ProgramEgress{}, err
		}
		out.Allow = append(out.Allow, pattern)
	}
	return out, nil
}

func (b *builder) buildMCP(m mcpLayer) (MCPServer, error) {
	if !namePattern.MatchString(m.Name) {
		return MCPServer{}, fmt.Errorf("mcp %q: name it with lowercase letters, digits and dashes", m.Name)
	}
	server := MCPServer{Name: m.Name, Command: m.Command, Env: m.Env, URL: m.URL, Secret: m.Secret}
	holds := len(m.Allow) > 0 || len(m.Approve) > 0 || len(m.Deny) > 0 || m.Default != ""
	switch {
	case len(m.Command) > 0 && m.URL != "":
		return MCPServer{}, fmt.Errorf("mcp %s: set command for a local server or url for a remote one, not both", m.Name)
	case len(m.Command) > 0:
		if m.Secret != "" {
			return MCPServer{}, fmt.Errorf("mcp %s: secret is for remote servers; a local one reads its own config", m.Name)
		}
		if holds {
			return MCPServer{}, fmt.Errorf("mcp %s: allow, approve, deny and default need a remote server: a local one talks to the agent where doriath cannot see", m.Name)
		}
		return server, nil
	case m.URL == "":
		return MCPServer{}, fmt.Errorf("mcp %s: set command or url", m.Name)
	}
	u, err := url.Parse(m.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
		return MCPServer{}, fmt.Errorf("mcp %s: url %q: want an https URL on port 443", m.Name, m.URL)
	}
	if len(m.Env) > 0 {
		return MCPServer{}, fmt.Errorf("mcp %s: env is for local servers", m.Name)
	}
	host := strings.ToLower(u.Hostname())
	rules, err := mcpRules(m, u.EscapedPath())
	if err != nil {
		return MCPServer{}, err
	}
	if m.Secret == "" && !holds {
		b.allow = appendNew(b.allow, host)
		return server, nil
	}
	var cred *credentialLayer
	if m.Secret != "" {
		if !namePattern.MatchString(m.Secret) {
			return MCPServer{}, fmt.Errorf("mcp %s: secret %q: use lowercase letters, digits and dashes", m.Name, m.Secret)
		}
		cred = &credentialLayer{Secret: m.Secret, Scheme: string(SchemeBearer)}
	}
	if i := slices.IndexFunc(b.http, func(x httpLayer) bool { return strings.EqualFold(x.Host, host) }); i >= 0 {
		if b.http[i].Credential == nil {
			b.http[i].Credential = cred
		}
		b.http[i].Rules = append(b.http[i].Rules, rules...)
		return server, nil
	}
	b.http = append(b.http, httpLayer{Host: host, Credential: cred, Default: string(ActionApprove), Rules: rules})
	return server, nil
}

func mcpRules(m mcpLayer, endpoint string) ([]ruleLayer, error) {
	if endpoint == "" {
		endpoint = "/"
	}
	summary := "Call " + m.Name + " tool"
	var rules []ruleLayer
	for _, l := range []struct {
		tools  []string
		action Action
	}{{m.Deny, ActionDeny}, {m.Approve, ActionApprove}, {m.Allow, ActionAllow}} {
		if len(l.tools) > 0 {
			rules = append(rules, ruleLayer{Method: "POST", Path: "/**", MCPTools: l.tools, Action: string(l.action), Summary: summary})
		}
	}
	other := ActionAllow
	switch Action(m.Default) {
	case "", ActionAllow:
	case ActionApprove, ActionDeny:
		other = Action(m.Default)
	default:
		return nil, fmt.Errorf("mcp %s: default %q: want allow, approve or deny", m.Name, m.Default)
	}
	return append(rules,
		ruleLayer{Method: "POST", Path: "/**", MCPTools: []string{"*"}, Action: string(other), Summary: summary},
		ruleLayer{Method: "POST", Path: endpoint, MCPNone: true, Action: string(ActionAllow)},
		ruleLayer{Method: "GET", Path: endpoint, Action: string(ActionAllow)},
		ruleLayer{Method: "DELETE", Path: endpoint, Action: string(ActionAllow)},
	), nil
}

func validGlob(g string) bool {
	_, err := path.Match(g, "")
	return g != "" && err == nil
}

// GitDir stands for every git directory doriath guards, submodules' stores
// included, in a mount that only gives one of their files an edit rule.
const GitDir = "{git}"

var gitEditable = []string{"config"}

func addGitEdit(p *Profile, name string, m mountLayer) error {
	if !slices.Contains(gitEditable, name) {
		return fmt.Errorf("%s/ names only %s, which doriath already keeps read-only", GitDir, strings.Join(gitEditable, ", "))
	}
	if m.Edit == nil {
		return errors.New("a mount of a git directory's file sets only its edit rule; add edit")
	}
	if m.Mode != "" && m.Mode != string(ModeRead) {
		return errors.New("doriath keeps it read-only; leave mode out")
	}
	e, err := buildEdit(m.Edit, ModeRead)
	if err != nil {
		return err
	}
	if p.GitEdits == nil {
		p.GitEdits = map[string]*Edit{}
	}
	if old := p.GitEdits[name]; old != nil {
		e.Safe = append(old.Safe, e.Safe...)
	}
	p.GitEdits[name] = e
	return nil
}

func buildEdit(l *editLayer, mode Mode) (*Edit, error) {
	if l == nil {
		return nil, nil
	}
	if mode != ModeRead {
		return nil, errors.New("edit is for read-only files; a writable file needs no request")
	}
	e := &Edit{Format: EditFormat(l.Format)}
	switch e.Format {
	case FormatGitConfig:
	case FormatText:
		if len(l.Safe) > 0 {
			return nil, errors.New("safe needs a format with settings, such as git-config: a text file has none")
		}
	default:
		return nil, fmt.Errorf("edit format %q: want git-config or text", l.Format)
	}
	for _, s := range l.Safe {
		key, value, ok := strings.Cut(s, " = ")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("edit safe %q: want KEY = VALUE, such as \"branch.*.merge = refs/heads/**\"", s)
		}
		e.Safe = append(e.Safe, SafeChange{Key: strings.ToLower(key), Value: value})
	}
	return e, nil
}
