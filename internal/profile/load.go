package profile

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/secret"
)

type Loader struct {
	Profiles       fs.FS
	Modules        []fs.FS
	Repository     fs.FS
	RepositoryRoot string
	Home           string
	User           string
	Private        []string
	Builtins       []string
}

const (
	RepoPrefix   = "repo:"
	RepoProfiles = ".doriath"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// secretNamePattern lets a secret name carry separators, such as
// "forgejo:fnune:repos:write". A name never holds a slash, because the keyring
// account is PROFILE/NAME, and starts with a letter or digit.
var secretNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9:_.-]*$`)

const secretNameRule = "use lowercase letters, digits, dashes, colons, underscores and dots, and start with a letter or digit"

const maxProfileDepth = 8

func (l *Loader) Names() ([]string, error) {
	files, err := l.files()
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(files)), nil
}

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

// Load reads a profile, or several joined with "+", such as
// work+review. Each later profile applies over the earlier
// ones as a module does: access adds up, and where two give the same mount,
// the lesser access holds. Two that give one secret different sources, or
// different signing keys, are refused.
func (l *Loader) Load(name string) (*Profile, error) {
	names := strings.Split(name, "+")
	var layers []layer
	var tops []layer
	var stateNames []string
	done := map[string]bool{}
	if err := l.collect(l.Builtins, &layers, nil, done); err != nil {
		return nil, err
	}
	for i := range layers {
		layers[i].builtin = true
	}
	for i, n := range names {
		if !namePattern.MatchString(strings.TrimPrefix(n, RepoPrefix)) {
			return nil, fmt.Errorf("profile name %q: use lowercase letters, digits and dashes", n)
		}
		if slices.Contains(names[:i], n) {
			return nil, fmt.Errorf("profile %q: %s is named twice", name, n)
		}
		top, err := l.readProfile(n)
		if err != nil {
			return nil, err
		}
		top.stateName = l.stateName(n)
		stateNames = append(stateNames, top.stateName)
		if i > 0 {
			top.source = "profile " + n
		}
		if err := l.collect(top.Modules, &layers, nil, done); err != nil {
			return nil, fmt.Errorf("profile %q: %w", n, err)
		}
		layers = append(layers, top)
		tops = append(tops, top)
	}

	b := newBuilder(l.Home)
	b.user = l.User
	b.private = l.Private
	b.apply(defaults)
	for _, ly := range layers {
		b.apply(ly)
	}
	top := tops[0]
	if len(names) > 1 {
		top.Name = name
	}
	if len(tops) > 1 {
		top.Description = composedDescription(tops)
		b.errs = append(b.errs, clashes(tops)...)
	}
	p, err := b.build(top)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	p.stateName = strings.Join(stateNames, "+")
	return p, nil
}

func (l *Loader) stateName(name string) string {
	if !strings.HasPrefix(name, RepoPrefix) {
		return name
	}
	sum := sha256.Sum256([]byte(l.RepositoryRoot))
	return name + "@" + hex.EncodeToString(sum[:4])
}

func (l *Loader) readProfile(name string) (layer, error) {
	data, err := l.profileData(name)
	if err != nil {
		return layer{}, err
	}
	top, err := decodeLayer("profile "+name, data)
	if err != nil {
		return layer{}, err
	}
	if top.Name != "" && top.Name != name {
		return layer{}, fmt.Errorf("profile %q: name field says %q", name, top.Name)
	}
	if len(top.UsesSecrets) > 0 {
		return layer{}, fmt.Errorf("profile %q: uses_secrets is for modules; a profile may use any secret of the session", name)
	}
	top.Name = name
	top.source = "profile"
	return top, nil
}

func composedDescription(tops []layer) string {
	var parts []string
	for _, t := range tops {
		if t.Description != "" {
			parts = append(parts, t.Description)
		}
	}
	return strings.Join(parts, "; ")
}

func clashes(tops []layer) []error {
	var errs []error
	secretFrom := map[string]layer{}
	signingFrom := ""
	signing := ""
	for _, t := range tops {
		for _, name := range slices.Sorted(maps.Keys(t.Secrets)) {
			if prev, ok := secretFrom[name]; ok && !reflect.DeepEqual(prev.Secrets[name], t.Secrets[name]) {
				errs = append(errs, fmt.Errorf("secret %q: profiles %s and %s give it different sources", name, prev.Name, t.Name))
				continue
			}
			secretFrom[name] = t
		}
		if t.Signing != nil && t.Signing.Key != "" {
			if signing != "" && signing != t.Signing.Key {
				errs = append(errs, fmt.Errorf("signing: profiles %s and %s sign with different keys", signingFrom, t.Name))
			}
			signing, signingFrom = t.Signing.Key, t.Name
		}
	}
	return errs
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
		data, shipped, err := l.readModule(name)
		if err != nil {
			return err
		}
		ly, err := decodeLayer("module "+name, data)
		if err != nil {
			return err
		}
		if ly.Name != "" || len(ly.Secrets) > 0 && !shipped {
			return fmt.Errorf("module %q: name and secrets belong in profiles", name)
		}
		for _, k := range slices.Sorted(maps.Keys(ly.Secrets)) {
			if v := ly.Secrets[k]; v.OAuth == nil || len(v.Command) > 0 || v.Keyring || v.File != "" {
				return fmt.Errorf("module %q: secret %q: a built-in module can define only a login with oauth", name, k)
			}
		}
		for _, ref := range ly.secretRefs() {
			if !slices.Contains(ly.UsesSecrets, ref) {
				return fmt.Errorf("module %q: it hands secret %q to a credential, signing or an MCP server, so list it in uses_secrets", name, ref)
			}
		}
		if err := l.collect(ly.Modules, out, append(stack, name), done); err != nil {
			return err
		}
		done[name] = true
		ly.source = name
		ly.shipped = shipped
		*out = append(*out, ly)
	}
	return nil
}

func (l *Loader) CheckModule(name string) error {
	var layers []layer
	return l.collect([]string{name}, &layers, nil, map[string]bool{})
}

// ShippedSource is a source of modules that doriath ships, as opposed to the
// modules in your folder. Only a shipped module can define a login. The
// embedded modules count too, so only a copy of them needs the method.
type ShippedSource interface {
	fs.FS
	Shipped()
}

func isShipped(src fs.FS) bool {
	if _, ok := src.(embed.FS); ok {
		return true
	}
	_, ok := src.(ShippedSource)
	return ok
}

func (l *Loader) readModule(name string) ([]byte, bool, error) {
	if strings.HasPrefix(name, RepoPrefix) {
		return nil, false, fmt.Errorf("module %s: %s names a repository profile, so add it to the profile name instead, such as my-app+%s", name, RepoPrefix, name)
	}
	if !namePattern.MatchString(name) {
		return nil, false, fmt.Errorf("module name %q: use lowercase letters, digits and dashes", name)
	}
	var found [][]byte
	shipped := false
	for _, src := range l.Modules {
		data, err := fs.ReadFile(src, path.Join(name+".toml"))
		if err == nil {
			found = append(found, data)
			shipped = isShipped(src)
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, false, fmt.Errorf("read module %q: %w", name, err)
		}
	}
	switch len(found) {
	case 0:
		return nil, false, fmt.Errorf("module %q not found", name)
	case 1:
		return found[0], shipped, nil
	}
	return nil, false, fmt.Errorf("module %q: your modules folder has a module with the name of a built-in module. Rename yours, such as my-%s, and list that name", name, name)
}

func (l *Loader) profileData(name string) ([]byte, error) {
	if rest, ok := strings.CutPrefix(name, RepoPrefix); ok {
		return l.repoProfileData(rest)
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
	return data, nil
}

func (l *Loader) repoProfileData(name string) ([]byte, error) {
	if l.Repository == nil {
		return nil, fmt.Errorf("profile %s: doriath reads it from %s in the repository, and found no repository with that folder", RepoPrefix+name, RepoProfiles)
	}
	data, err := fs.ReadFile(l.Repository, name+".toml")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("profile %s not found: the repository has no %s/%s.toml", RepoPrefix+name, RepoProfiles, name)
	}
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", RepoPrefix+name, err)
	}
	return data, nil
}

type builder struct {
	home        string
	user        string
	private     []string
	refuse      []string
	warn        []warnLayer
	hold        []holdLayer
	deny        []string
	mounts      []mountLayer
	caches      []string
	devices     []string
	envSet      map[string]string
	notes       map[string]string
	envPass     []string
	envPath     []string
	programs    []programsLayer
	allow       []string
	ports       []int
	tcp         []int
	http        []httpLayer
	signing     string
	unsigned    bool
	podman      bool
	images      []string
	nix         bool
	vcsStore    bool
	clipboard   bool
	mcp         []mcpLayer
	open        []openLayer
	forwards    []forwardLayer
	harden      Hardening
	archives    []string
	libraries   []string
	limits      Limits
	claude      claudeLayer
	disable     bool
	agent       agentLayer
	secrets     map[string]secretLayer
	secretOwner map[string]string
	errs        []error
	modules     []string
	sources     map[string][]string

	repositoryGrants map[string]RepositoryGrant

	yourUses, repositoryUses []secretUse
}

func newBuilder(home string) *builder {
	return &builder{home: home, envSet: map[string]string{}, notes: map[string]string{}, secrets: map[string]secretLayer{}, secretOwner: map[string]string{}, sources: map[string][]string{}, repositoryGrants: map[string]RepositoryGrant{}, limits: Limits{Tasks: DefaultTaskLimit, Memory: DefaultMemoryLimit}}
}

func (b *builder) from(source, key string) {
	b.sources[key] = appendNew(b.sources[key], source)
}

func (b *builder) apply(l layer) {
	if !strings.HasPrefix(l.source, "profile") && l.source != defaultsSource && !l.builtin {
		b.modules = append(b.modules, l.source)
		b.recordRepositoryGrant(l)
	}
	b.record(l)
	if l.fromRepository() {
		b.repositoryUses = append(b.repositoryUses, l.secretUses()...)
	} else {
		b.yourUses = append(b.yourUses, l.secretUses()...)
	}
	if l.fromRepository() {
		b.errs = append(b.errs, b.repositoryOverrides(l)...)
		b.errs = append(b.errs, b.repositoryMounts(l)...)
	}
	b.mounts = append(b.mounts, l.Mounts...)
	b.applyPaths(l.Paths)
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
	for h, note := range l.Egress.Notes {
		b.notes[h] = note
	}
	b.programs = append(b.programs, l.Egress.Programs...)
	b.open = append(slices.Clone(l.Open), b.open...)
	b.forwards = append(b.forwards, l.Forward...)
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
	if l.Clipboard != nil && l.Clipboard.Images != nil {
		b.clipboard = *l.Clipboard.Images
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
	if c := l.Code; c != nil {
		for _, a := range c.Archives {
			b.archives = appendNew(b.archives, a)
		}
		for _, l := range c.Libraries {
			b.libraries = appendNew(b.libraries, l)
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
		for _, s := range c.AllowedMCPServers {
			b.claude.AllowedMCPServers = appendNew(b.claude.AllowedMCPServers, s)
		}
		for _, s := range c.Ask {
			b.claude.Ask = appendNew(b.claude.Ask, s)
		}
		for _, s := range c.Deny {
			b.claude.Deny = appendNew(b.claude.Deny, s)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(l.Secrets)) {
		v := l.Secrets[k]
		if v.File != "" {
			b.errs = append(b.errs, fmt.Errorf("secret %q: doriath no longer reads secrets from files, so that none stays on your disk. Use keyring = true, and store the value with `doriath profiles login PROFILE %s`, which reads it from standard input", k, k))
			continue
		}
		if l.fromRepository() && len(v.Command) > 0 {
			b.errs = append(b.errs, fmt.Errorf("secret %q: a repository profile cannot run a command on your machine. Define the secret in a profile of your own, and start the session with both, such as my-app+%s", k, l.profileName()))
			continue
		}
		if l.fromRepository() && v.GitHubApp != nil {
			b.errs = append(b.errs, fmt.Errorf("secret %q: a repository profile cannot mint tokens with a key of yours. Define the secret in a profile of your own, and start the session with both, such as my-app+%s", k, l.profileName()))
			continue
		}
		if l.fromRepository() && v.Keyring {
			b.errs = append(b.errs, fmt.Errorf("secret %q: a repository profile cannot read your keyring. Define the secret in a profile of your own, and start the session with both, such as my-app+%s", k, l.profileName()))
			continue
		}
		b.secrets[k] = v
		switch {
		case strings.HasPrefix(l.source, "profile"):
			b.secretOwner[k] = l.stateName
		case l.shipped:
			b.secretOwner[k] = SharedOwnerPrefix + l.source
		}
	}
}

// secretUse is a secret sent to one place: a host for a credential, or the
// URL of an MCP server.
type secretUse struct {
	secret, place string
	mcp, defined  bool
}

func (l layer) secretUses() []secretUse {
	var uses []secretUse
	for _, h := range l.HTTP {
		credentials := []*credentialLayer{h.Credential}
		for _, r := range h.Rules {
			credentials = append(credentials, r.Credential)
		}
		for _, c := range credentials {
			if c != nil && c.Secret != "" {
				_, own := l.Secrets[c.Secret]
				uses = append(uses, secretUse{secret: c.Secret, place: strings.ToLower(h.Host), defined: own})
			}
		}
	}
	for _, m := range l.MCP {
		if m.Secret != "" {
			_, own := l.Secrets[m.Secret]
			uses = append(uses, secretUse{secret: m.Secret, place: m.URL, mcp: true, defined: own})
		}
	}
	return uses
}

func (b *builder) repositorySecretUses() []error {
	var errs []error
	seen := map[secretUse]bool{}
	for _, use := range b.repositoryUses {
		if seen[use] {
			continue
		}
		seen[use] = true
		if use.defined || slices.ContainsFunc(b.yourUses, func(y secretUse) bool {
			return y.secret == use.secret && y.place == use.place && y.mcp == use.mcp
		}) {
			continue
		}
		if use.mcp {
			errs = append(errs, fmt.Errorf("mcp server %s: secret %q: a repository profile can use a secret only with a URL that your own profile already uses it with. Add an [[mcp]] with this url and secret to a profile of your own first", use.place, use.secret))
			continue
		}
		errs = append(errs, fmt.Errorf("http %s: secret %q: a repository profile can send a secret only to a host that your own profile already attaches it to. Attach %q to %s in a profile of your own first", use.place, use.secret, use.secret, use.place))
	}
	return errs
}

// repeatsCredential is a repository entry that only names the credential
// your profiles already attach to the host, with nothing to change.
func repeatsCredential(repo, yours httpLayer) bool {
	return repo.Credential != nil && reflect.DeepEqual(*repo.Credential, *yours.Credential) && len(repo.Rules) == 0 && repo.Default == ""
}

func (b *builder) repositoryOverrides(l layer) []error {
	var errs []error
	yours := "your profiles or modules"
	for _, h := range l.HTTP {
		i := slices.IndexFunc(b.http, func(x httpLayer) bool { return hostsOverlap(x.Host, h.Host) })
		repeats := i >= 0 && b.http[i].Credential != nil && repeatsCredential(h, b.http[i])
		switch {
		case repeats:
		case i >= 0 && b.http[i].Credential != nil:
			errs = append(errs, fmt.Errorf("http %s: %s already give it a credential, and a repository profile cannot change what the credential reaches. Put the rules in a profile of your own", h.Host, yours))
		case i >= 0 && h.hasSettings():
			errs = append(errs, fmt.Errorf("http %s: %s already define %s, and a repository profile cannot add rules or settings to it. Put them in a profile of your own", h.Host, yours, b.http[i].Host))
		}
	}
	for _, port := range slices.Concat(l.Egress.Ports, l.Egress.TCPPorts) {
		errs = append(errs, fmt.Errorf("egress port %d: a repository profile cannot reach a port on your machine, because the services there may trust a local client. Put the port in a profile of your own", port))
	}
	if l.Code != nil && (len(l.Code.Archives) > 0 || len(l.Code.Libraries) > 0) {
		errs = append(errs, errors.New("code: a repository profile cannot name archives or libraries that programs trust with a credential. Put them in a profile of your own"))
	}
	for _, m := range l.MCP {
		if slices.ContainsFunc(b.mcp, func(x mcpLayer) bool { return x.Name == m.Name }) {
			errs = append(errs, fmt.Errorf("mcp %s: %s already define it, and a repository profile cannot replace it", m.Name, yours))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(l.Secrets)) {
		if _, taken := b.secrets[k]; taken {
			errs = append(errs, fmt.Errorf("secret %q: %s already define it, and a repository profile cannot replace it", k, yours))
		}
	}
	for _, f := range l.Forward {
		errs = append(errs, fmt.Errorf("forward %s: a repository profile cannot forward a port, because programs on your machine would reach the jail through it. Put the forward in a profile of your own", f.Port))
	}
	return errs
}

func hostsOverlap(a, b string) bool {
	return strings.EqualFold(a, b) || HostPattern(strings.ToLower(a)).Covers(HostPattern(strings.ToLower(b))) || HostPattern(strings.ToLower(b)).Covers(HostPattern(strings.ToLower(a)))
}

func (h httpLayer) hasSettings() bool {
	return len(h.Rules) > 0 || h.Default != "" || h.Credential != nil || h.SSH != nil || h.Operation != nil || len(h.Only) > 0 || len(h.Repositories) > 0 || h.EncodedSlashes
}

func (b *builder) repositoryMounts(l layer) []error {
	var errs []error
	for _, m := range l.Mounts {
		if m.Edit != nil {
			for _, safe := range m.Edit.Safe {
				key, _, _ := strings.Cut(safe, " = ")
				if k := strings.ToLower(strings.TrimSpace(key)); slices.ContainsFunc(gitKeysThatRunOrSend, func(d string) bool { return mayMatch(k, d) }) {
					errs = append(errs, fmt.Errorf("mount %s: edit safe %q: a repository profile cannot let a setting that runs a program or sends data change without your answer. Put it in a profile of your own", m.Path, safe))
				}
			}
		}
		if _, placeholder := placeholderPath(m.Path); placeholder || strings.HasPrefix(m.Path, GitDir+"/") || m.Mode == string(ModeHide) {
			continue
		}
		path, err := b.expand(m.Path)
		if err != nil {
			continue
		}
		for _, private := range b.privatePaths() {
			if within(path, private) || within(private, path) {
				errs = append(errs, fmt.Errorf("mount %s: a repository profile cannot show %s, because it holds keys, logins, config that names programs your machine runs, or the state of doriath. Put the mount in a profile of your own", m.Path, private))
				break
			}
		}
	}
	return errs
}

func (b *builder) privatePaths() []string {
	out := slices.Clone(b.private)
	for _, raw := range b.refuse {
		if _, placeholder := placeholderPath(raw); placeholder {
			continue
		}
		if path, err := b.expand(raw); err == nil {
			out = append(out, path)
		}
	}
	return out
}

var gitKeysThatRunOrSend = []string{
	"credential.*", "url.*", "include.*", "includeif.*", "http.*", "sendemail.*", "remote.*", "submodule.*",
	"alias.*", "filter.*", "diff.*", "merge.*", "pager.*", "gpg.*", "protocol.*", "uploadpack.*", "receive.*",
	"core.sshcommand", "core.askpass", "core.hookspath", "core.fsmonitor", "core.editor", "core.pager",
	"core.gitproxy", "core.worktree", "sequence.editor", "user.signingkey",
}

func mayMatch(safe, pattern string) bool {
	prefix, isPrefix := strings.CutSuffix(pattern, "*")
	if !isPrefix {
		return regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(safe), `\*`, ".*") + "$").MatchString(pattern)
	}
	for i := range prefix {
		switch {
		case i == len(safe):
			return false
		case safe[i] == '*':
			return true
		case safe[i] != prefix[i]:
			return false
		}
	}
	return true
}

func (l layer) fromRepository() bool {
	return strings.HasPrefix(l.source, "profile") && strings.HasPrefix(l.Name, RepoPrefix)
}

func (l layer) profileName() string {
	return l.Name
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
		if !strings.HasPrefix(l.source, "profile") {
			continue
		}
		for _, r := range h.Rules {
			b.from(l.source, fmt.Sprintf("rule %s %s %s: %s", h.Host, r.Method, r.Path, r.Action))
		}
	}
	for _, port := range l.Egress.Ports {
		b.from(l.source, fmt.Sprintf("port %d: HTTP", port))
	}
	for _, port := range l.Egress.TCPPorts {
		b.from(l.source, fmt.Sprintf("port %d: TCP", port))
	}
	if l.Code != nil {
		for _, a := range l.Code.Archives {
			b.from(l.source, "code archive "+a)
		}
		for _, lib := range l.Code.Libraries {
			b.from(l.source, "code library "+lib)
		}
	}
	for _, k := range l.Env.Pass {
		b.from(l.source, "env pass "+k)
	}
	for k := range l.Env.Set {
		b.from(l.source, "env set "+k)
	}
	for _, m := range l.MCP {
		b.from(l.source, "mcp "+m.Name)
		if u, err := url.Parse(m.URL); err == nil && u.Hostname() != "" {
			b.from(l.source, "http "+strings.ToLower(u.Hostname()))
		}
	}
	if l.Podman != nil {
		for _, img := range l.Podman.Images {
			b.from(l.source, "image "+img)
		}
	}
	for k, v := range l.Secrets {
		b.from(l.source, "secret "+k)
		b.from(l.source, "source "+k+": "+describeSecretSource(v))
	}
	for _, k := range l.UsesSecrets {
		b.from(l.source, "secret "+k+" for "+l.source)
	}
	b.recordDecisions(l)
}

func describeSecretSource(v secretLayer) string {
	switch {
	case len(v.Command) > 0:
		return "command " + strings.Join(v.Command, " ")
	case v.Keyring:
		return "keyring"
	case v.GitHubApp != nil:
		return fmt.Sprintf("token of GitHub App %d", v.GitHubApp.AppID)
	case v.OAuth != nil && v.OAuth.MCP != "":
		return "login to MCP server " + v.OAuth.MCP
	case v.OAuth != nil && v.OAuth.AuthorizeURL != "":
		return "login at " + v.OAuth.AuthorizeURL
	case v.OAuth != nil:
		return "login at " + v.OAuth.Issuer
	}
	return "unset"
}

// appKeyErrors checks the secrets that hold the private key of a GitHub App.
// The key stays on your machine, so nothing may send it anywhere: no
// credential, MCP server or signing key can use it.
func appKeyErrors(p *Profile) []error {
	var errs []error
	keyOf := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(p.Secrets)) {
		a := p.Secrets[name].GitHubApp
		if a == nil {
			continue
		}
		key, ok := p.Secrets[a.Key]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("secret %q: github_app key %q: add it under [secrets.%s] in the profile", name, a.Key, cli.TOMLKey(a.Key)))
		case a.Key == name || key.GitHubApp != nil || key.OAuth != nil:
			errs = append(errs, fmt.Errorf("secret %q: github_app key %q must hold the private key itself, from a command or the keyring", name, a.Key))
		default:
			keyOf[a.Key] = name
		}
	}
	refuse := func(key, use string) {
		if app, ok := keyOf[key]; ok {
			errs = append(errs, fmt.Errorf("secret %q: it holds the private key of the GitHub App in %q, which stays on your machine, so %s cannot use it", key, app, use))
		}
	}
	for _, h := range p.HTTP {
		creds := []*Credential{h.Credential}
		for _, r := range h.Rules {
			creds = append(creds, r.Credential)
		}
		for _, c := range creds {
			if c != nil {
				refuse(c.Secret, "the credential for "+string(h.Host))
			}
		}
	}
	for _, m := range p.MCP {
		if m.Secret != "" {
			refuse(m.Secret, "the MCP server "+m.Name)
		}
	}
	if p.SigningKey != "" {
		refuse(p.SigningKey, "the signing key")
	}
	return errs
}

func (b *builder) recordDecisions(l layer) {
	describeCredential := func(c *credentialLayer) string {
		programs := "any program"
		if len(c.Binaries) > 0 {
			programs = strings.Join(c.Binaries, ", ")
		}
		return c.Secret + " for " + programs
	}
	for _, h := range l.HTTP {
		if h.Credential != nil {
			b.from(l.source, "credential "+h.Host+": "+describeCredential(h.Credential))
		}
		if h.Default != "" {
			b.from(l.source, "default "+h.Host+": "+h.Default)
		}
		for _, r := range h.Rules {
			if r.Credential != nil {
				b.from(l.source, "credential "+h.Host+" "+r.Method+" "+r.Path+": "+describeCredential(r.Credential))
			}
		}
	}
	for _, o := range l.Open {
		b.from(l.source, "open "+o.Host+" "+o.Path+": "+o.Action)
	}
	for _, f := range l.Forward {
		b.from(l.source, "forward "+string(f.Port))
	}
	for _, m := range l.Mounts {
		if m.Edit != nil && len(m.Edit.Safe) > 0 {
			b.from(l.source, "setting edit "+m.Path+": safe without asking: "+strings.Join(m.Edit.Safe, "; "))
		}
	}
	setting := func(key string, value any) {
		b.from(l.source, fmt.Sprintf("setting %s = %v", key, value))
	}
	if l.Nix != nil && l.Nix.Daemon != nil {
		setting("nix.daemon", *l.Nix.Daemon)
	}
	if l.Podman != nil && l.Podman.Enabled != nil {
		setting("podman.enabled", *l.Podman.Enabled)
	}
	if l.VCS != nil && l.VCS.Store != nil {
		setting("vcs.store", *l.VCS.Store)
	}
	if l.Clipboard != nil && l.Clipboard.Images != nil {
		setting("clipboard.images", *l.Clipboard.Images)
	}
	if h := l.Hardening; h != nil {
		if h.Namespaces != nil {
			setting("hardening.namespaces", *h.Namespaces)
		}
		if h.Ptrace != nil {
			setting("hardening.ptrace", *h.Ptrace)
		}
		if h.Landlock != nil {
			setting("hardening.landlock", *h.Landlock)
		}
	}
	if s := l.Signing; s != nil {
		if s.Key != "" {
			setting("signing.key", s.Key)
		}
		if s.Enable != nil {
			setting("signing.enable", *s.Enable)
		}
	}
	if lim := l.Limits; lim != nil {
		if lim.Tasks != nil {
			setting("limits.tasks", *lim.Tasks)
		}
		if lim.Memory != "" {
			setting("limits.memory", lim.Memory)
		}
		if lim.CPU != "" {
			setting("limits.cpu", lim.CPU)
		}
	}
	if a := l.Agent; a != nil && len(a.Instructions) > 0 {
		setting("agent.instructions", strings.Join(a.Instructions, ", "))
	}
	if c := l.Claude; c != nil {
		if c.DisableConnectors != nil {
			setting("claude.disable_connectors", *c.DisableConnectors)
		}
		if len(c.AllowedMCPServers) > 0 {
			setting("claude.allowed_mcp_servers", strings.Join(c.AllowedMCPServers, ", "))
		}
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
	if h.Operation != nil {
		cur.Operation = h.Operation
	}
	for _, o := range h.Only {
		cur.Only = appendNew(cur.Only, o)
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
	errs := slices.Clone(b.errs)
	errs = append(errs, b.repositorySecretUses()...)
	p := &Profile{
		Name:            top.Name,
		Description:     top.Description,
		Env:             Env{Set: map[string]string{}},
		Podman:          b.podman,
		ContainerImages: b.images,
		NixDaemon:       b.nix,
		VCSStore:        b.vcsStore,
		ClipboardImages: b.clipboard,
		Hardening:       b.harden,
		Limits:          b.limits,
		Secrets:         map[string]secret.Backend{},
		SecretOwners:    b.secretOwner,
		Modules:         b.modules,
		Sources:         b.sources,

		RepositoryGrants: b.repositoryGrants,
	}
	for _, m := range b.mounts {
		if name, ok := strings.CutPrefix(m.Path, GitDir+"/"); ok {
			if err := addGitEdit(p, name, m); err != nil {
				errs = append(errs, fmt.Errorf("mount %s: %w", m.Path, err))
			}
			continue
		}
		if strings.Contains(m.Path, User) && b.user == "" {
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
		missing := Missing(m.Missing)
		if _, ok := strictness[missing]; m.Missing != "" && !ok {
			errs = append(errs, fmt.Errorf("mount %s: missing %q: want error, skip or hold", m.Path, m.Missing))
			continue
		}
		e, err := buildEdit(m.Edit, mode)
		if err != nil {
			errs = append(errs, fmt.Errorf("mount %s: %w", m.Path, err))
			continue
		}
		p.Mounts = mergeKeepingLessAccess(p.Mounts, Mount{Path: path, Mode: mode, Missing: missing, Edit: e})
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
	for _, a := range b.archives {
		path, err := b.expand(a)
		if err != nil || !filepath.IsAbs(path) {
			errs = append(errs, fmt.Errorf("code archive %q: a path must be absolute or start with ~/", a))
			continue
		}
		p.CodeArchives = append(p.CodeArchives, path)
	}
	for _, l := range b.libraries {
		path, err := b.expand(l)
		if err != nil || !filepath.IsAbs(path) {
			errs = append(errs, fmt.Errorf("code library %q: a path must be absolute or start with ~/", l))
			continue
		}
		p.CodeLibraries = append(p.CodeLibraries, path)
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
	for _, o := range b.open {
		rule, err := buildOpen(o)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p.Open = append(p.Open, rule)
	}
	forwards, forwardErrs := buildForwards(b.forwards)
	p.Forwards = forwards
	errs = append(errs, forwardErrs...)
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
	for h, note := range b.notes {
		pattern, err := ParseHostPattern(h)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress notes: %w", err))
			continue
		}
		if p.Egress.Notes == nil {
			p.Egress.Notes = map[HostPattern]string{}
		}
		p.Egress.Notes[pattern] = note
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
		if !secretNamePattern.MatchString(name) {
			errs = append(errs, fmt.Errorf("secret %q: %s", name, secretNameRule))
			continue
		}
		backend := secret.Backend{Command: s.Command, Keyring: s.Keyring, Required: s.Required || name == b.signing}
		if s.Refresh != "" {
			d, err := time.ParseDuration(s.Refresh)
			if err != nil {
				errs = append(errs, fmt.Errorf("secret %q: refresh %q: want a duration like 45m", name, s.Refresh))
				continue
			}
			backend.Refresh = d
		}
		if a := s.GitHubApp; a != nil {
			backend.GitHubApp = &secret.GitHubApp{AppID: a.AppID, Key: a.Key, Permissions: a.Permissions, Repositories: a.Repositories}
		}
		if o := s.OAuth; o != nil {
			backend.OAuth = &secret.OAuth{MCP: o.MCP, Issuer: o.Issuer, AuthorizeURL: o.AuthorizeURL, TokenURL: o.TokenURL, TokenBody: o.TokenBody, ClientID: o.ClientID, Scopes: o.Scopes}
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
			errs = append(errs, fmt.Errorf("signing key %q: add it under [secrets.%s] in the profile", b.signing, cli.TOMLKey(b.signing)))
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
				errs = append(errs, fmt.Errorf("http %s: secret %q: add it under [secrets.%s] in the profile", h.Host, c.Secret, cli.TOMLKey(c.Secret)))
			}
		}
	}
	errs = append(errs, appKeyErrors(p)...)
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
	rules, pathErrs := b.buildPaths()
	errs = append(errs, pathErrs...)
	p.PathRules = rules
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
	for _, o := range h.Only {
		only, err := ParseHostPattern(o)
		if err != nil || !host.Covers(only) {
			return HTTPHost{}, fmt.Errorf("http %s only %q: want a host or pattern within %s", h.Host, o, h.Host)
		}
		out.Only = append(out.Only, only)
	}
	if o := h.Operation; o != nil {
		if o.Header != "" && !headerName.MatchString(o.Header) {
			return HTTPHost{}, fmt.Errorf("http %s operation header %q: want a header name such as X-Amz-Target", h.Host, o.Header)
		}
		out.Operation = Operation{Header: http.CanonicalHeaderKey(o.Header), Form: o.Form}
	}
	if h.Default != "" {
		action, err := parseAction(h.Default)
		if err != nil {
			return HTTPHost{}, fmt.Errorf("http %s default: %w", h.Host, err)
		}
		out.Default = action
	}
	if c := h.Credential; c != nil {
		cred, err := b.buildCredential(*c)
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
		rule, err := b.buildRule(r)
		if err != nil {
			return HTTPHost{}, fmt.Errorf("http %s rule: %w", h.Host, err)
		}
		out.Rules = append(out.Rules, rule)
	}
	return out, nil
}

func (b *builder) buildCredential(c credentialLayer) (Credential, error) {
	if !secretNamePattern.MatchString(c.Secret) {
		return Credential{}, fmt.Errorf("secret %q: %s", c.Secret, secretNameRule)
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
	if c.Field != "" && scheme != SchemeWebSocket {
		return Credential{}, fmt.Errorf("field is only used with the websocket scheme")
	}
	if c.KeyID != "" && scheme != SchemeSigV4 {
		return Credential{}, fmt.Errorf("key_id is only used with the sigv4 scheme")
	}
	switch scheme {
	case SchemeBearer, SchemeToken, SchemeSigV4:
	case SchemeBasic:
		if c.Username == "" {
			return Credential{}, fmt.Errorf("the basic scheme needs a username")
		}
	case SchemeWebSocket:
		if !jsonField.MatchString(c.Field) {
			return Credential{}, fmt.Errorf("the websocket scheme needs the name of a field, such as oauth_token")
		}
	case SchemeHeader:
		if !headerName.MatchString(c.Header) {
			return Credential{}, fmt.Errorf("the header scheme needs a header name, such as PRIVATE-TOKEN")
		}
	default:
		return Credential{}, fmt.Errorf("scheme %q: want bearer, token, basic, header, sigv4 or websocket", c.Scheme)
	}
	var binaries []string
	for _, bin := range c.Binaries {
		if bin == "" {
			return Credential{}, fmt.Errorf("binaries entries must not be empty")
		}
		if strings.Contains(bin, "/") {
			expanded, err := b.expand(bin)
			if err != nil {
				return Credential{}, fmt.Errorf("binary %q: a path must be absolute or start with ~/", bin)
			}
			bin = expanded
		}
		binaries = append(binaries, bin)
	}
	return Credential{Secret: c.Secret, Scheme: scheme, Username: c.Username, Field: c.Field, Header: http.CanonicalHeaderKey(c.Header), KeyID: c.KeyID, Binaries: binaries}, nil
}

var jsonField = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var methodPattern = regexp.MustCompile(`^(\*|[A-Z]+)$`)

func (b *builder) buildRule(r ruleLayer) (Rule, error) {
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
	if slices.Contains(r.BodyLinePrefix, "") {
		return Rule{}, fmt.Errorf("body_line_prefix entries must not be empty")
	}
	if r.Header != "" && !headerName.MatchString(r.Header) {
		return Rule{}, fmt.Errorf("header %q: want a header name such as x-api-key", r.Header)
	}
	if r.HeaderPrefix != "" && r.Header == "" {
		return Rule{}, fmt.Errorf("header_prefix needs header")
	}
	switch {
	case r.HeaderGlob != "" && r.Header == "":
		return Rule{}, fmt.Errorf("header_glob needs header")
	case r.HeaderGlob != "" && r.HeaderPrefix != "":
		return Rule{}, fmt.Errorf("set header_prefix or header_glob, not both")
	case r.HeaderGlob != "" && !validGlob(r.HeaderGlob):
		return Rule{}, fmt.Errorf("header_glob %q: want a glob such as DynamoDB_*.DeleteTable", r.HeaderGlob)
	}
	for name, g := range r.Form {
		if name == "" || !validGlob(g) {
			return Rule{}, fmt.Errorf("form %s = %q: want a field name and a value or glob, such as Action = \"DeleteStack\"", name, g)
		}
	}
	for _, g := range r.MCPTools {
		if !validGlob(g) {
			return Rule{}, fmt.Errorf("mcp_tools %q: want a tool name or a glob such as notion-create-*", g)
		}
	}
	var refs []RefPattern
	for _, s := range r.Refs {
		p, err := ParseRefPattern(s)
		if err != nil {
			return Rule{}, err
		}
		refs = append(refs, p)
	}
	rule := Rule{Method: method, Path: path, Refs: refs, BodyContains: r.BodyContains, BodyLinePrefix: r.BodyLinePrefix, Header: http.CanonicalHeaderKey(r.Header), HeaderPrefix: r.HeaderPrefix, HeaderGlob: r.HeaderGlob, Form: r.Form, MCPTools: r.MCPTools, MCPNone: r.MCPNone, Action: action, Summary: r.Summary, MCPServer: r.MCPServer}
	if rule.Subject, err = ParseTemplate(r.Subject); err != nil {
		return Rule{}, fmt.Errorf("subject %w", err)
	}
	if r.Link != nil {
		if r.Link.Label == "" {
			return Rule{}, fmt.Errorf("link needs a label, such as \"Open PR\"")
		}
		u, err := ParseLinkTemplate(r.Link.URL)
		if err != nil {
			return Rule{}, fmt.Errorf("link url %w", err)
		}
		rule.Link = &RuleLink{Label: r.Link.Label, URL: u}
	}
	if r.GraphQL != nil {
		g, err := buildGraphQL(*r.GraphQL)
		if err != nil {
			return Rule{}, err
		}
		rule.GraphQL = &g
	}
	if r.Credential != nil {
		cred, err := b.buildCredential(*r.Credential)
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

func buildOpen(o openLayer) (OpenRule, error) {
	host, err := ParseHostPattern(o.Host)
	if err != nil {
		return OpenRule{}, fmt.Errorf("open %s: %w", o.Host, err)
	}
	path := o.Path
	if path == "" {
		path = "/**"
	}
	pattern, err := ParsePathPattern(path)
	if err != nil {
		return OpenRule{}, fmt.Errorf("open %s: %w", o.Host, err)
	}
	action := ActionApprove
	if o.Action != "" {
		if action, err = parseAction(o.Action); err != nil {
			return OpenRule{}, fmt.Errorf("open %s: %w", o.Host, err)
		}
	}
	return OpenRule{Host: host, Path: pattern, Action: action, ForwardRedirect: o.ForwardRedirect}, nil
}

func buildForwards(layers []forwardLayer) ([]PortForward, []error) {
	var out []PortForward
	var errs []error
	for _, f := range layers {
		host, jail, err := ParseForward(string(f.Port))
		if err != nil {
			errs = append(errs, fmt.Errorf("forward %s: %w", f.Port, err))
			continue
		}
		i := slices.IndexFunc(out, func(x PortForward) bool { return x.Host == host })
		switch {
		case i < 0:
			out = append(out, PortForward{Name: f.Name, Host: host, Jail: jail})
		case out[i].Jail != jail:
			errs = append(errs, fmt.Errorf("forward %s: port %d on your machine already forwards to port %d in the jail", f.Port, host, out[i].Jail))
		case f.Name != "":
			out[i].Name = f.Name
		}
	}
	return out, errs
}

func parseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case ActionAllow, ActionApprove, ActionDeny:
		return a, nil
	}
	return "", fmt.Errorf("action %q: want allow, approve or deny", s)
}

func (b *builder) buildAgent() (Agent, error) {
	var a Agent
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
		AllowedMCPServers: b.claude.AllowedMCPServers,
		DeniedMCPServers:  b.claude.DeniedMCPServers,
		Ask:               b.claude.Ask,
		Deny:              b.claude.Deny,
	}
}

func (b *builder) expand(p string) (string, error) {
	if strings.Contains(p, User) {
		if b.user == "" {
			return "", fmt.Errorf("path %q: %s is unknown", p, User)
		}
		p = strings.ReplaceAll(p, User, b.user)
	}
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
	if m.Secret == "" && !holds {
		b.allow = appendNew(b.allow, host)
		return server, nil
	}
	var cred *credentialLayer
	if m.Secret != "" {
		if !secretNamePattern.MatchString(m.Secret) {
			return MCPServer{}, fmt.Errorf("mcp %s: secret %q: %s", m.Name, m.Secret, secretNameRule)
		}
		cred = &credentialLayer{Secret: m.Secret, Scheme: string(SchemeBearer)}
	}
	rules, err := mcpRules(m, u.EscapedPath(), cred)
	if err != nil {
		return MCPServer{}, err
	}
	if i := slices.IndexFunc(b.http, func(x httpLayer) bool { return strings.EqualFold(x.Host, host) }); i >= 0 {
		b.http[i].Rules = append(b.http[i].Rules, rules...)
		return server, nil
	}
	b.http = append(b.http, httpLayer{Host: host, Default: string(ActionApprove), Rules: rules})
	return server, nil
}

func mcpRules(m mcpLayer, endpoint string, cred *credentialLayer) ([]ruleLayer, error) {
	if endpoint == "" {
		endpoint = "/"
	}
	summary := "Call " + m.Name + " tool"
	var rules []ruleLayer
	if len(m.Deny) > 0 {
		rules = append(rules, ruleLayer{Method: "POST", Path: "/**", MCPTools: m.Deny, Action: string(ActionDeny), Summary: summary, MCPServer: m.Name})
	}
	for _, l := range []struct {
		tools  []string
		action Action
	}{{m.Approve, ActionApprove}, {m.Allow, ActionAllow}} {
		if len(l.tools) > 0 {
			rules = append(rules, ruleLayer{Method: "POST", Path: endpoint, MCPTools: l.tools, Action: string(l.action), Summary: summary, MCPServer: m.Name, Credential: cred})
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
		ruleLayer{Method: "POST", Path: endpoint, MCPTools: []string{"*"}, Action: string(other), Summary: summary, MCPServer: m.Name, Credential: cred},
		ruleLayer{Method: "POST", Path: endpoint, MCPNone: true, Action: string(ActionAllow), Credential: cred},
		ruleLayer{Method: "GET", Path: endpoint, Action: string(ActionAllow), Credential: cred},
		ruleLayer{Method: "DELETE", Path: endpoint, Action: string(ActionAllow), Credential: cred},
	), nil
}

func validGlob(g string) bool {
	_, err := path.Match(g, "")
	return g != "" && err == nil
}

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
