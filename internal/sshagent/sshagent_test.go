package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
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
	a, err := New(newKey(t), "girdle agent", []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	line := string(a.AuthorizedKey())
	if !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.HasSuffix(line, " girdle agent\n") {
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
