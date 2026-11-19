package edit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/profile"
)

const MaxSize = 512 << 10

type Change struct {
	Key           string
	Old           []string
	New           []string
	namesNoRemote bool
}

func Changes(ctx context.Context, git string, format profile.EditFormat, old, new []byte) ([]Change, error) {
	if len(new) > MaxSize {
		return nil, fmt.Errorf("the new content is larger than %d bytes", MaxSize)
	}
	switch format {
	case profile.FormatGitConfig:
		return gitChanges(ctx, git, old, new)
	case profile.FormatText, "":
		if bytes.Equal(old, new) {
			return nil, nil
		}
		return []Change{{Old: lines(old), New: lines(new)}}, nil
	}
	return nil, fmt.Errorf("unknown edit format %q", format)
}

func lines(b []byte) []string {
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func gitChanges(ctx context.Context, git string, old, new []byte) ([]Change, error) {
	before, err := gitSettings(ctx, git, old)
	if err != nil {
		return nil, fmt.Errorf("read the current file: %w", err)
	}
	after, err := gitSettings(ctx, git, new)
	if err != nil {
		return nil, fmt.Errorf("read the new content as git config: %w", err)
	}
	var keys []string
	for _, s := range [][]setting{before, after} {
		for _, e := range s {
			if !slices.Contains(keys, e.key) {
				keys = append(keys, e.key)
			}
		}
	}
	var out []Change
	for _, k := range keys {
		o, n := values(before, k), values(after, k)
		if !slices.Equal(o, n) {
			out = append(out, Change{Key: k, Old: o, New: n, namesNoRemote: namesNoRemote(k, n, after)})
		}
	}
	return out, nil
}

func namesNoRemote(key string, names []string, after []setting) bool {
	if !isRemoteSetting(key) {
		return false
	}
	return slices.ContainsFunc(names, func(name string) bool {
		return name != "." && len(values(after, "remote."+name+".url")) == 0
	})
}

func isRemoteSetting(key string) bool {
	key = strings.ToLower(key)
	return key == "remote.pushdefault" || strings.HasPrefix(key, "branch.") && (strings.HasSuffix(key, ".remote") || strings.HasSuffix(key, ".pushremote"))
}

type setting struct{ key, value string }

func values(s []setting, key string) []string {
	var out []string
	for _, e := range s {
		if e.key == key {
			out = append(out, e.value)
		}
	}
	return out
}

func gitSettings(ctx context.Context, git string, content []byte) ([]setting, error) {
	f, err := os.CreateTemp("", "doriath-edit-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	out, err := runGit(ctx, git, "config", "--no-includes", "--file", f.Name(), "--list", "-z")
	if err != nil {
		return nil, err
	}
	var s []setting
	for _, rec := range strings.Split(out, "\x00") {
		if rec == "" {
			continue
		}
		key, value, _ := strings.Cut(rec, "\n")
		s = append(s, setting{key: key, value: value})
	}
	return s, nil
}

func Safe(c Change, rules []profile.SafeChange) bool {
	if c.Key == "" || c.namesNoRemote {
		return false
	}
	return slices.ContainsFunc(rules, func(r profile.SafeChange) bool {
		if !keyPattern(r.Key).MatchString(strings.ToLower(c.Key)) {
			return false
		}
		v := valuePattern(r.Value)
		return !slices.ContainsFunc(c.New, func(n string) bool { return !v.MatchString(n) })
	})
}

func keyPattern(glob string) *regexp.Regexp {
	return regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(strings.ToLower(glob)), `\*`, ".*") + "$")
}

func valuePattern(glob string) *regexp.Regexp {
	q := regexp.QuoteMeta(glob)
	q = strings.ReplaceAll(q, `\*\*`, "\x00")
	q = strings.ReplaceAll(q, `\*`, "[^/:]*")
	q = strings.ReplaceAll(q, "\x00", ".*")
	return regexp.MustCompile("^" + q + "$")
}

func Describe(changes []Change, rules []profile.SafeChange) string {
	var b strings.Builder
	for _, c := range changes {
		if c.Key == "" {
			b.WriteString(textDiff(c.Old, c.New))
			continue
		}
		mark := ""
		if !Safe(c, rules) {
			mark = "  (not on the safe list)"
		}
		switch {
		case len(c.New) == 0:
			fmt.Fprintf(&b, "remove %s%s\n", c.Key, mark)
		default:
			for _, v := range c.New {
				fmt.Fprintf(&b, "set %s = %s%s\n", c.Key, v, mark)
			}
		}
	}
	return b.String()
}

func textDiff(old, new []string) string {
	var b strings.Builder
	keep := commonLines(old, new)
	i, j := 0, 0
	for _, k := range keep {
		for ; old[i] != k; i++ {
			fmt.Fprintf(&b, "- %s\n", old[i])
		}
		for ; new[j] != k; j++ {
			fmt.Fprintf(&b, "+ %s\n", new[j])
		}
		i, j = i+1, j+1
	}
	for ; i < len(old); i++ {
		fmt.Fprintf(&b, "- %s\n", old[i])
	}
	for ; j < len(new); j++ {
		fmt.Fprintf(&b, "+ %s\n", new[j])
	}
	return b.String()
}

func commonLines(a, b []string) []string {
	if len(a)*len(b) > 4_000_000 {
		return nil
	}
	n := make([][]int, len(a)+1)
	for i := range n {
		n[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				n[i][j] = n[i+1][j+1] + 1
			} else {
				n[i][j] = max(n[i+1][j], n[i][j+1])
			}
		}
	}
	var out []string
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i, j = i+1, j+1
		case n[i+1][j] >= n[i][j+1]:
			i++
		default:
			j++
		}
	}
	return out
}

type Checked struct {
	path    string
	dev     uint64
	ino     uint64
	Content []byte
}

const maxCurrent = 4 << 20

func Check(path string) (Checked, error) {
	f, err := openStrict(path, os.O_RDONLY)
	if err != nil {
		return Checked{}, err
	}
	defer f.Close()
	st, err := regular(f)
	if err != nil {
		return Checked{}, fmt.Errorf("%s: %w", path, err)
	}
	content, err := io.ReadAll(io.LimitReader(f, maxCurrent+1))
	if err != nil {
		return Checked{}, err
	}
	if len(content) > maxCurrent {
		return Checked{}, fmt.Errorf("%s is larger than %d bytes", path, maxCurrent)
	}
	return Checked{path: path, dev: st.Dev, ino: st.Ino, Content: content}, nil
}

func openStrict(path string, flags int) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s without a symlink in its path: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func regular(f *os.File) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("not a regular file")
	}
	return &st, nil
}

func Apply(ctx context.Context, git string, checked Checked, format profile.EditFormat, new []byte, changes []Change) error {
	f, err := openStrict(checked.path, os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := regular(f)
	if err != nil {
		return fmt.Errorf("%s: %w", checked.path, err)
	}
	if st.Dev != checked.dev || st.Ino != checked.ino {
		return fmt.Errorf("%s is another file than the one that doriath showed you", checked.path)
	}
	current, err := io.ReadAll(io.LimitReader(f, maxCurrent+1))
	if err != nil {
		return err
	}
	content := new
	switch format {
	case profile.FormatGitConfig:
		if content, err = applyGit(ctx, git, current, changes); err != nil {
			return err
		}
	default:
		if !bytes.Equal(current, checked.Content) {
			return fmt.Errorf("%s changed after doriath showed it to you", checked.path)
		}
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.WriteAt(content, 0)
	return err
}

func applyGit(ctx context.Context, git string, current []byte, changes []Change) ([]byte, error) {
	dir, err := os.MkdirTemp("", "doriath-edit-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	tmp := filepath.Join(dir, "config")
	if err := os.WriteFile(tmp, current, 0o600); err != nil {
		return nil, err
	}
	for _, c := range changes {
		if c.Key == "" {
			return nil, errors.New("a git config edit has a change without a setting")
		}
		if _, err := runGit(ctx, git, "config", "--file", tmp, "--unset-all", c.Key); err != nil && !notSet(err) {
			return nil, err
		}
		for _, v := range c.New {
			if _, err := runGit(ctx, git, "config", "--file", tmp, "--add", c.Key, v); err != nil {
				return nil, err
			}
		}
	}
	return os.ReadFile(tmp)
}

func notSet(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 5
}

func runGit(ctx context.Context, git string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, git, args...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}
