package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func sshsig(namespace string) []byte {
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, Hash string
		Digest                    []byte
	}{namespace, "", "sha512", make([]byte, 64)})...)
}

func TestSignOnlySSHSIGInAllowedNamespaces(t *testing.T) {
	a, err := New(newKey(t), "agent", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	pub := a.PublicKey()
	sig, err := a.Sign(pub, sshsig("git"))
	if err != nil {
		t.Fatalf("git signature refused: %v", err)
	}
	if err := pub.Verify(sshsig("git"), sig); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(pub, sshsig("file")); !errors.Is(err, ErrNamespace) {
		t.Fatalf("other namespace: err = %v", err)
	}
	authData := ssh.Marshal(struct{ Session []byte }{make([]byte, 32)})
	if _, err := a.Sign(pub, authData); !errors.Is(err, ErrNotSSHSIG) {
		t.Fatalf("auth data: err = %v", err)
	}
	if _, err := a.Sign(pub, []byte("SSHSIGgarbage")); !errors.Is(err, ErrNotSSHSIG) {
		t.Fatalf("garbage: err = %v", err)
	}
	if err := a.Add(agent.AddedKey{}); !errors.Is(err, ErrReadOnly) {
		t.Fatal("Add must be refused")
	}
}

func TestAuthorizedKey(t *testing.T) {
	a, err := New(newKey(t), "doriath agent", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	line := string(a.AuthorizedKey())
	if !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.HasSuffix(line, " doriath agent\n") {
		t.Fatalf("line = %q", line)
	}
}

func TestRejectsBadInput(t *testing.T) {
	if _, err := New([]byte("not a key"), "", []string{"git"}); err == nil {
		t.Fatal("want parse error")
	}
	if _, err := New(newKey(t), "", nil); err == nil {
		t.Fatal("want namespace error")
	}
}

func TestKeyChangesAreRefusedOverTheSocket(t *testing.T) {
	a, err := New(newKey(t), "agent", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	go func() { _ = agent.ServeAgent(a, server) }()
	c := agent.NewClient(client)

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, change := range map[string]func() error{
		"add":        func() error { return c.Add(agent.AddedKey{PrivateKey: other}) },
		"remove":     func() error { return c.Remove(a.PublicKey()) },
		"remove all": c.RemoveAll,
		"lock":       func() error { return c.Lock([]byte("pw")) },
		"unlock":     func() error { return c.Unlock([]byte("pw")) },
	} {
		if err := change(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := c.Extension("session-bind@openssh.com", nil); err == nil {
		t.Error("extension accepted")
	}
	keys, err := c.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "agent" {
		t.Fatalf("keys after the attempts = %v, %v", keys, err)
	}
	if _, err := c.Sign(a.PublicKey(), sshsig("git")); err != nil {
		t.Fatalf("the agent stopped signing after a lock attempt: %v", err)
	}
	if _, err := a.Signers(); !errors.Is(err, ErrReadOnly) {
		t.Fatal("Signers must not hand out the key")
	}
}

func TestSignRefusesOtherKeysAndHashes(t *testing.T) {
	a, err := New(newKey(t), "agent", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := New(newKey(t), "", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(stranger.PublicKey(), sshsig("git")); err == nil || err.Error() != "unknown key" {
		t.Fatalf("another key: err = %v", err)
	}
	md5 := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, Hash string
		Digest                    []byte
	}{"git", "", "md5", make([]byte, 16)})...)
	if _, err := a.Sign(a.PublicKey(), md5); !errors.Is(err, ErrNotSSHSIG) {
		t.Fatalf("md5: err = %v", err)
	}
}

func TestRSAKeySignsWithTheRequestedAlgorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(pem.EncodeToMemory(block), "", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	for flags, want := range map[agent.SignatureFlags]string{
		agent.SignatureFlagRsaSha512: ssh.KeyAlgoRSASHA512,
		agent.SignatureFlagRsaSha256: ssh.KeyAlgoRSASHA256,
	} {
		sig, err := a.SignWithFlags(a.PublicKey(), sshsig("git"), flags)
		if err != nil || sig.Format != want {
			t.Errorf("flags %d: %v, %v; want %s", flags, sig, err, want)
		}
	}
}

// TestWithSSHKeygen checks the real client: ssh-keygen signs in the git
// namespace through the agent socket, and fails in another namespace.
func TestWithSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	a, err := New(newKey(t), "agent", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = a.Serve(l) }()

	pubPath := filepath.Join(dir, "key.pub")
	msgPath := filepath.Join(dir, "msg")
	if err := os.WriteFile(pubPath, a.AuthorizedKey(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(msgPath, []byte("tree abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sign := func(ns string) error {
		cmd := exec.Command(keygen, "-Y", "sign", "-n", ns, "-f", pubPath, msgPath)
		cmd.Env = []string{"SSH_AUTH_SOCK=" + sock, "HOME=" + dir}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return errors.New(string(out))
		}
		return nil
	}
	if err := sign("git"); err != nil {
		t.Fatalf("git namespace: %v", err)
	}
	if _, err := os.Stat(msgPath + ".sig"); err != nil {
		t.Fatal("no signature written")
	}
	_ = os.Remove(msgPath + ".sig")
	if err := sign("file"); err == nil {
		t.Fatal("file namespace must fail")
	}
}
