package vcs

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const fileWorkers = 8

func walkParallel(root string, visit func(p string, d fs.DirEntry, err error) (work func() error, _ error)) error {
	jobs := make(chan func() error)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	failed := func() error {
		mu.Lock()
		defer mu.Unlock()
		return first
	}
	for range fileWorkers {
		wg.Go(func() {
			for job := range jobs {
				if err := job(); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}
		})
	}
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err := failed(); err != nil {
			return err
		}
		work, err := visit(p, d, err)
		if work != nil {
			jobs <- work
		}
		return err
	})
	close(jobs)
	wg.Wait()
	if err := failed(); err != nil {
		return err
	}
	return walkErr
}

func removeTree(dir string) error {
	err := walkParallel(dir, func(p string, d fs.DirEntry, err error) (func() error, error) {
		if err != nil || d.IsDir() {
			return nil, nil
		}
		return func() error {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}, nil
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}
