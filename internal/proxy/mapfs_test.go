package proxy

import (
	"io/fs"
	"testing/fstest"
)

type mapFS map[string]string

func (m mapFS) Open(name string) (fs.File, error) {
	fsys := fstest.MapFS{}
	for k, v := range m {
		fsys[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return fsys.Open(name)
}
