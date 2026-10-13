// Package sshagent serves an ssh-agent that holds one key and only signs
// SSHSIG messages in allowed namespaces. git signs commits that way, while
// SSH authentication signs session data, which this agent refuses. So the
// key can sign commits but cannot log in anywhere.
package sshagent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrNotSSHSIG = errors.New("this agent only signs SSHSIG messages")
	ErrNamespace = errors.New("namespace not allowed")
	ErrReadOnly  = errors.New("this agent does not accept key changes")
	sshsigMagic  = []byte("SSHSIG")
)

type Agent struct {
	signer     ssh.Signer
	comment    string
	namespaces []string
}

// New parses an OpenSSH private key. The key must not have a passphrase,
// because the agent runs without anyone to type it.
func New(privateKey []byte, comment string, namespaces []string) (*Agent, error) {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	if len(namespaces) == 0 {
		return nil, errors.New("at least one signing namespace is needed")
	}
	return &Agent{signer: signer, comment: comment, namespaces: namespaces}, nil
}

func (a *Agent) PublicKey() ssh.PublicKey { return a.signer.PublicKey() }

// AuthorizedKey is the public key in the one-line format that git's
// user.signingkey and GitHub accept.
func (a *Agent) AuthorizedKey() []byte {
	line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(a.signer.PublicKey()))
	if a.comment != "" {
		line = append(line, ' ')
		line = append(line, a.comment...)
	}
	return append(line, '\n')
}

func (a *Agent) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_ = agent.ServeAgent(a, conn)
		}()
	}
}

func (a *Agent) List() ([]*agent.Key, error) {
	pub := a.signer.PublicKey()
	return []*agent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: a.comment}}, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !bytes.Equal(key.Marshal(), a.signer.PublicKey().Marshal()) {
		return nil, errors.New("unknown key")
	}
	ns, err := sshsigNamespace(data)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(a.namespaces, ns) {
		return nil, fmt.Errorf("%w: %q", ErrNamespace, ns)
	}
	if as, ok := a.signer.(ssh.AlgorithmSigner); ok {
		switch {
		case flags&agent.SignatureFlagRsaSha512 != 0:
			return as.SignWithAlgorithm(nil, data, ssh.KeyAlgoRSASHA512)
		case flags&agent.SignatureFlagRsaSha256 != 0:
			return as.SignWithAlgorithm(nil, data, ssh.KeyAlgoRSASHA256)
		}
	}
	return a.signer.Sign(nil, data)
}

// sshsigNamespace reads the namespace from the data ssh-keygen -Y sign asks
// the agent to sign: the magic preamble, then namespace, reserved, hash
// algorithm and message hash as SSH strings (PROTOCOL.sshsig).
func sshsigNamespace(data []byte) (string, error) {
	rest, ok := bytes.CutPrefix(data, sshsigMagic)
	if !ok {
		return "", ErrNotSSHSIG
	}
	var blob struct {
		Namespace string
		Reserved  string
		Hash      string
		Digest    []byte
	}
	if err := ssh.Unmarshal(rest, &blob); err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotSSHSIG, err)
	}
	if blob.Hash != "sha256" && blob.Hash != "sha512" {
		return "", fmt.Errorf("%w: hash %q", ErrNotSSHSIG, blob.Hash)
	}
	return blob.Namespace, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) { return nil, ErrReadOnly }

func (a *Agent) Add(agent.AddedKey) error   { return ErrReadOnly }
func (a *Agent) Remove(ssh.PublicKey) error { return ErrReadOnly }
func (a *Agent) RemoveAll() error           { return ErrReadOnly }
func (a *Agent) Lock([]byte) error          { return ErrReadOnly }
func (a *Agent) Unlock([]byte) error        { return ErrReadOnly }

func (a *Agent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var _ agent.ExtendedAgent = (*Agent)(nil)
