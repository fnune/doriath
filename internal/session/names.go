package session

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/config"
)

var (
	adjectives = []string{
		"amber", "brave", "brisk", "calm", "clever", "cosy", "crisp", "curly",
		"dapper", "dusky", "eager", "fancy", "fluffy", "fond", "frosty", "gentle",
		"giddy", "glad", "golden", "grand", "happy", "hardy", "hazel", "honest",
		"jolly", "keen", "kind", "lively", "lucky", "mellow", "merry", "misty",
		"modest", "nimble", "noble", "plucky", "polite", "proud", "quick", "quiet",
		"rosy", "rustic", "sandy", "shy", "silky", "sleepy", "smart", "snowy",
		"snug", "sober", "spry", "steady", "stout", "sunny", "swift", "tidy",
		"tiny", "tender", "velvet", "warm", "wavy", "wily", "witty", "zesty",
	}
	animals = []string{
		"badger", "beaver", "bison", "crane", "crow", "deer", "dingo", "dove",
		"eagle", "egret", "elk", "falcon", "ferret", "finch", "fox", "gecko",
		"goose", "hare", "hawk", "heron", "ibex", "ibis", "koala", "lark",
		"lemur", "lion", "llama", "lynx", "marten", "mole", "moose", "newt",
		"okapi", "orca", "otter", "owl", "panda", "puffin", "quail", "rabbit",
		"raven", "robin", "salmon", "seal", "shrew", "skunk", "sloth", "snail",
		"sparrow", "squid", "stoat", "swan", "tapir", "tern", "tiger", "toad",
		"trout", "turtle", "vole", "walrus", "weasel", "whale", "wolf", "wren",
	}
)

const maxNameTries = 64

func newID(paths config.Paths) (string, error) {
	if err := os.MkdirAll(paths.Sessions(), 0o700); err != nil {
		return "", fmt.Errorf("create sessions directory: %w", err)
	}
	for range maxNameTries {
		id := adjectives[rand.IntN(len(adjectives))] + "-" + animals[rand.IntN(len(animals))]
		if backupExists(paths, id) {
			continue
		}
		err := os.Mkdir(filepath.Join(paths.Sessions(), id), 0o700)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create session directory: %w", err)
		}
		return id, nil
	}
	return "", fmt.Errorf("every session name is taken: end some sessions, or remove old backups with %s", cli.Code("doriath clean"))
}

func backupExists(paths config.Paths, id string) bool {
	for _, p := range []string{filepath.Join(paths.Backups(), id), recordPath(paths, id)} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}
