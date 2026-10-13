package profile

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
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

func (l *Loader) Names() ([]string, error) {
	entries, err := fs.ReadDir(l.Profiles, ".")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".toml"); ok && !e.IsDir() && !strings.HasSuffix(name, ".local") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (l *Loader) Load(name string) (*Profile, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("profile name %q: use lowercase letters, digits and dashes", name)
	}
	data, err := fs.ReadFile(l.Profiles, name+".toml")
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

	var layers []layer
	if err := l.collect(top.Modules, &layers, nil, map[string]bool{}); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	layers = append(layers, top)
	local, err := l.localLayer(name)
	if err != nil {
		return nil, err
	}
	if local != nil {
		layers = append(layers, *local)
	}

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

// Find returns the profile whose match paths contain dir, preferring the
// longest match.
func (l *Loader) Find(dir string) (*Profile, error) {
	names, err := l.Names()
	if err != nil {
		return nil, err
	}
	var best *Profile
	bestLen := -1
	for _, name := range names {
		p, err := l.Load(name)
		if err != nil {
			return nil, err
		}
		for _, m := range p.Match {
			if within(dir, m) && len(m) > bestLen {
				best, bestLen = p, len(m)
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no profile matches %s: pass --profile or add the directory to a profile's match list", dir)
	}
	return best, nil
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
		if ly.Name != "" || len(ly.Match) > 0 {
			return fmt.Errorf("module %q: name and match belong in profiles", name)
		}
		if err := l.collect(ly.Modules, out, append(stack, name), done); err != nil {
			return err
		}
		done[name] = true
		*out = append(*out, ly)
	}
	return nil
}

// LocalFile is where girdle keeps changes the person approved from a session,
// so the profile they wrote stays as they wrote it.
func LocalFile(name string) string { return name + ".local.toml" }

func (l *Loader) localLayer(name string) (*layer, error) {
	data, err := fs.ReadFile(l.Profiles, LocalFile(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", LocalFile(name), err)
	}
	ly, err := decodeLayer(LocalFile(name), data)
	if err != nil {
		return nil, err
	}
	if ly.Name != "" || len(ly.Match) > 0 || len(ly.Modules) > 0 {
		return nil, fmt.Errorf("%s: name, match and modules belong in the profile itself", LocalFile(name))
	}
	return &ly, nil
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
	home    string
	mounts  []mountLayer
	caches  []string
	devices []string
	envSet  map[string]string
	envPass []string
	allow   []string
	ports   []int
	tcp     []int
	http    []httpLayer
	signing string
	podman  bool
	images  []string
	nix     bool
	harden  Hardening
	limits  Limits
	claude  claudeLayer
	disable bool
	mcp     *[]string
	status  bool
	share   bool
	secrets map[string]string
}

func newBuilder(home string) *builder {
	return &builder{home: home, envSet: map[string]string{}, secrets: map[string]string{}, limits: Limits{Tasks: DefaultTaskLimit}}
}

func (b *builder) apply(l layer) {
	for _, m := range l.Mounts {
		i := slices.IndexFunc(b.mounts, func(x mountLayer) bool { return x.Path == m.Path })
		if i >= 0 {
			b.mounts[i] = m
		} else {
			b.mounts = append(b.mounts, m)
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
	for _, h := range l.Egress.Allow {
		b.allow = appendNew(b.allow, h)
	}
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
		b.signing = l.Signing.Key
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
	if c := l.Claude; c != nil {
		if c.DisableConnectors != nil {
			b.disable = *c.DisableConnectors
		}
		if c.MCPServers != nil {
			servers := append([]string{}, *c.MCPServers...)
			b.mcp = &servers
		}
		if c.StatusLine != nil {
			b.status = *c.StatusLine
		}
		if c.ShareLogin != nil {
			b.share = *c.ShareLogin
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
		if c.ApprovalTimeout != "" {
			b.claude.ApprovalTimeout = c.ApprovalTimeout
		}
	}
	for k, v := range l.Secrets {
		b.secrets[k] = v
	}
}

// mergeHTTP lets a later layer override an earlier entry for the same host.
// Its rules go first, so that a profile can narrow what a module allows.
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
	cur.Rules = append(slices.Clone(h.Rules), cur.Rules...)
	b.http[i] = cur
}

func appendNew(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

var (
	limitValue = regexp.MustCompile(`^[0-9]+[KMGT]?$`)
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
		Hardening:       b.harden,
		Limits:          b.limits,
		Secrets:         b.secrets,
	}
	for _, m := range top.Match {
		path, err := b.expand(m)
		if err != nil {
			errs = append(errs, fmt.Errorf("match: %w", err))
			continue
		}
		p.Match = append(p.Match, path)
	}
	for _, m := range b.mounts {
		path, err := b.expand(m.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("mount: %w", err))
			continue
		}
		mode := Mode(m.Mode)
		if m.Mode == "" {
			mode = ModeReadOnly
		}
		if mode != ModeReadOnly && mode != ModeReadWrite && mode != ModeClone {
			errs = append(errs, fmt.Errorf("mount %s: mode %q: want ro, rw or clone", m.Path, m.Mode))
			continue
		}
		if m.Ref != "" && mode != ModeClone {
			errs = append(errs, fmt.Errorf("mount %s: ref only applies to clone mounts", m.Path))
			continue
		}
		if m.Live && mode != ModeReadWrite {
			errs = append(errs, fmt.Errorf("mount %s: live only applies to rw mounts", m.Path))
			continue
		}
		p.Mounts = append(p.Mounts, Mount{Path: path, Mode: mode, Optional: m.Optional, Ref: m.Ref, Live: m.Live})
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
	for _, h := range b.allow {
		pattern, err := ParseHostPattern(h)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress: %w", err))
			continue
		}
		p.Egress.Allow = append(p.Egress.Allow, pattern)
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
	if b.signing != "" {
		if !namePattern.MatchString(b.signing) {
			errs = append(errs, fmt.Errorf("signing key %q: use lowercase letters, digits and dashes", b.signing))
		}
		p.SigningKey = b.signing
	}
	if b.limits.Tasks < 0 {
		errs = append(errs, fmt.Errorf("limits tasks %d: must be zero (no limit) or more", b.limits.Tasks))
	}
	if b.limits.Memory != "" && !limitValue.MatchString(b.limits.Memory) {
		errs = append(errs, fmt.Errorf("limits memory %q: want a size such as 8G", b.limits.Memory))
	}
	if b.limits.CPU != "" && !cpuValue.MatchString(b.limits.CPU) {
		errs = append(errs, fmt.Errorf("limits cpu %q: want a percentage such as 200%%", b.limits.CPU))
	}
	claude, err := b.buildClaude()
	if err != nil {
		errs = append(errs, err)
	}
	p.Claude = claude
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
	out := HTTPHost{Host: host, Default: ActionAllow}
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
		// A request that carries the person's credential and that no rule
		// names waits for them, rather than going out in their name.
		if h.Default == "" {
			out.Default = ActionApprove
		}
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
	switch scheme {
	case SchemeBearer, SchemeToken:
		if c.Username != "" {
			return Credential{}, fmt.Errorf("username is only used with the basic scheme")
		}
	case SchemeBasic:
		if c.Username == "" {
			return Credential{}, fmt.Errorf("the basic scheme needs a username")
		}
	default:
		return Credential{}, fmt.Errorf("scheme %q: want bearer, token or basic", c.Scheme)
	}
	for _, b := range c.Binaries {
		if b == "" {
			return Credential{}, fmt.Errorf("binaries entries must not be empty")
		}
		if strings.Contains(b, "/") && !strings.HasPrefix(b, "/") {
			return Credential{}, fmt.Errorf("binary %q: a path must be absolute", b)
		}
	}
	return Credential{Secret: c.Secret, Scheme: scheme, Username: c.Username, Binaries: c.Binaries}, nil
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
	return Rule{Method: method, Path: path, BodyContains: r.BodyContains, Action: action, Summary: r.Summary}, nil
}

func parseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case ActionAllow, ActionApprove, ActionDeny:
		return a, nil
	}
	return "", fmt.Errorf("action %q: want allow, approve or deny", s)
}

func (b *builder) buildClaude() (Claude, error) {
	c := Claude{
		DisableConnectors: b.disable,
		StatusLine:        b.status,
		ShareLogin:        b.share,
		DeniedMCPServers:  b.claude.DeniedMCPServers,
		Ask:               b.claude.Ask,
		Deny:              b.claude.Deny,
		ApprovalTimeout:   defaultApprovalTimeout,
	}
	if b.claude.ApprovalTimeout != "" {
		d, err := time.ParseDuration(b.claude.ApprovalTimeout)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("claude approval_timeout %q: want a positive duration like 90s", b.claude.ApprovalTimeout)
		}
		c.ApprovalTimeout = d
	}
	if b.mcp != nil {
		c.MCPServers = append([]string{}, *b.mcp...)
	}
	return c, nil
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
