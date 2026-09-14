package daemon

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/lihongjie0209/passman/internal/platform"

	"golang.org/x/crypto/ssh"
	sshprotocol "golang.org/x/crypto/ssh/agent"
)

var errSSHAgentReadOnly = errors.New("passman SSH agent is read-only")

type passmanSSHAgent struct{ server *Server }

func (s *Server) listenSSHAgent(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	stat, ok := dirInfo.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	if !ok || uid < 0 || int64(stat.Uid) != int64(uid) || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("SSH agent directory must be owner-only and not a symlink")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace non-socket SSH agent path")
		}
		if conn, dialErr := netDial(path); dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("SSH agent is already running")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}

func (s *Server) acceptSSHAgent(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok || platform.VerifyPeer(unixConn) != nil {
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = sshprotocol.ServeAgent(&passmanSSHAgent{server: s}, conn)
		}()
	}
}

func (a *passmanSSHAgent) List() ([]*sshprotocol.Key, error) {
	a.server.mu.Lock()
	defer a.server.mu.Unlock()
	identities, err := a.identitiesLocked()
	if err != nil {
		return nil, err
	}
	keys := make([]*sshprotocol.Key, 0, len(identities))
	for _, identity := range identities {
		publicKey := identity.signer.PublicKey()
		keys = append(keys, &sshprotocol.Key{Format: publicKey.Type(), Blob: publicKey.Marshal(), Comment: identity.ref})
	}
	return keys, nil
}

func (a *passmanSSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *passmanSSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshprotocol.SignatureFlags) (*ssh.Signature, error) {
	a.server.mu.Lock()
	defer a.server.mu.Unlock()
	identities, err := a.identitiesLocked()
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		if !bytes.Equal(identity.signer.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		signature, err := signWithFlags(identity.signer, data, flags)
		if err != nil {
			return nil, err
		}
		if err := a.server.audit.Append("ssh_sign_allowed", []string{identity.ref}, "ssh-agent"); err != nil {
			return nil, errors.New("audit write failed; SSH signature denied")
		}
		return signature, nil
	}
	if err := a.server.audit.Append("ssh_sign_denied", nil, "ssh-agent"); err != nil {
		return nil, errors.New("audit write failed; SSH signature denied")
	}
	return nil, errors.New("SSH key not available")
}

func (a *passmanSSHAgent) Signers() ([]ssh.Signer, error) {
	a.server.mu.Lock()
	defer a.server.mu.Unlock()
	identities, err := a.identitiesLocked()
	if err != nil {
		return nil, err
	}
	signers := make([]ssh.Signer, 0, len(identities))
	for _, identity := range identities {
		signers = append(signers, identity.signer)
	}
	return signers, nil
}

func (*passmanSSHAgent) Add(sshprotocol.AddedKey) error { return errSSHAgentReadOnly }
func (*passmanSSHAgent) Remove(ssh.PublicKey) error     { return errSSHAgentReadOnly }
func (*passmanSSHAgent) RemoveAll() error               { return errSSHAgentReadOnly }
func (*passmanSSHAgent) Lock([]byte) error              { return errSSHAgentReadOnly }
func (*passmanSSHAgent) Unlock([]byte) error            { return errSSHAgentReadOnly }
func (*passmanSSHAgent) Extension(string, []byte) ([]byte, error) {
	return nil, sshprotocol.ErrExtensionUnsupported
}

type sshIdentity struct {
	ref    string
	signer ssh.Signer
}

func (a *passmanSSHAgent) identitiesLocked() ([]sshIdentity, error) {
	if a.server.data == nil {
		return nil, errors.New("vault is locked")
	}
	identities := make([]sshIdentity, 0)
	for entryName, entry := range a.server.data.Entries {
		field, ok := entry.Fields["private_key"]
		if !ok || !field.ExecOnly || field.ExpiresAt != nil && !time.Now().UTC().Before(*field.ExpiresAt) {
			continue
		}
		value := append([]byte(nil), field.Value...)
		signer, err := ssh.ParsePrivateKey(value)
		clear(value)
		if err != nil {
			continue
		}
		identities = append(identities, sshIdentity{ref: entryName + "#private_key", signer: signer})
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ref < identities[j].ref })
	return identities, nil
}

func signWithFlags(signer ssh.Signer, data []byte, flags sshprotocol.SignatureFlags) (*ssh.Signature, error) {
	if flags == 0 {
		return signer.Sign(rand.Reader, data)
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("requested SSH signature algorithm is unsupported")
	}
	var algorithm string
	switch flags {
	case sshprotocol.SignatureFlagRsaSha256:
		algorithm = ssh.KeyAlgoRSASHA256
	case sshprotocol.SignatureFlagRsaSha512:
		algorithm = ssh.KeyAlgoRSASHA512
	default:
		return nil, errors.New("unsupported SSH signature flags")
	}
	return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
}
