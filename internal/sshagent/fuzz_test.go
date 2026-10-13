package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

// signedNamespace reads the namespace the way ssh-keygen -Y verify does:
// the first string after the magic.
func signedNamespace(data []byte) (string, bool) {
	rest := data[len(sshsigMagic):]
	if len(rest) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(rest)
	if uint64(n) > uint64(len(rest)-4) {
		return "", false
	}
	return string(rest[4 : 4+n]), true
}

func FuzzSign(f *testing.F) {
	f.Add(sshsig("git"))
	f.Add(sshsig("file"))
	f.Add(sshsig("gitx"))
	f.Add(append(sshsig("git"), 0))
	f.Add([]byte("SSHSIG\x00\x00\x00\x03git"))
	f.Add([]byte("\x00\x00\x00\x20session-id"))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "fuzz")
	if err != nil {
		f.Fatal(err)
	}
	a, err := New(pem.EncodeToMemory(block), "agent", []string{"git"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := a.Sign(a.PublicKey(), data); err != nil {
			return
		}
		ns, ok := signedNamespace(data)
		if !ok || ns != "git" {
			t.Fatalf("signed %q, whose namespace reads as %q", data, ns)
		}
		blob := struct {
			Namespace, Reserved, Hash string
			Digest                    []byte
		}{}
		if err := ssh.Unmarshal(data[len(sshsigMagic):], &blob); err != nil {
			t.Fatal(err)
		}
		if again := append([]byte("SSHSIG"), ssh.Marshal(blob)...); string(again) != string(data) {
			t.Fatalf("signed %q, which carries bytes beyond the SSHSIG fields", data)
		}
	})
}
