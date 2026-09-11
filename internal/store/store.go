package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/lihongjie0209/passman/internal/secure"
	"github.com/lihongjie0209/passman/internal/vault"

	"filippo.io/age"
)

const (
	identityFile = "identity.age"
	vaultFile    = "vault.age"
)

type Store struct{ dir string }

func New(dir string) *Store           { return &Store{dir: dir} }
func (s *Store) Dir() string          { return s.dir }
func (s *Store) IdentityPath() string { return filepath.Join(s.dir, identityFile) }
func (s *Store) VaultPath() string    { return filepath.Join(s.dir, vaultFile) }

func (s *Store) Init(password []byte) error {
	if len([]rune(string(password))) < 12 {
		return errors.New("master password must contain at least 12 characters")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	if err := s.checkDir(); err != nil {
		return err
	}
	if _, err := os.Stat(s.IdentityPath()); err == nil {
		return errors.New("vault is already initialized")
	}
	id, err := secure.NewIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}
	encID, err := secure.EncryptIdentity(id, password)
	if err != nil {
		return err
	}
	data, err := json.Marshal(vault.New())
	if err != nil {
		return err
	}
	encVault, err := secure.EncryptVault(data, id.Recipient())
	clear(data)
	if err != nil {
		return err
	}
	if err := atomicWrite(s.IdentityPath(), encID); err != nil {
		return err
	}
	if err := atomicWrite(s.VaultPath(), encVault); err != nil {
		_ = os.Remove(s.IdentityPath())
		return err
	}
	return nil
}

func (s *Store) Unlock(password []byte) (*age.X25519Identity, *vault.Data, error) {
	if err := s.checkDir(); err != nil {
		return nil, nil, err
	}
	encID, err := readSecure(s.IdentityPath(), 4<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("reading identity: %w", err)
	}
	id, err := secure.DecryptIdentity(encID, password)
	if err != nil {
		return nil, nil, err
	}
	encVault, err := readSecure(s.VaultPath(), 64<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("reading vault: %w", err)
	}
	plain, err := secure.DecryptVault(encVault, id)
	if err != nil {
		return nil, nil, errors.New("vault authentication failed")
	}
	defer clear(plain)
	var data vault.Data
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, nil, errors.New("damaged vault payload")
	}
	if data.Version != vault.FormatVersion || data.Entries == nil {
		return nil, nil, errors.New("unsupported vault format")
	}
	return id, &data, nil
}

func (s *Store) Save(data *vault.Data, recipient age.Recipient) error {
	plain, err := json.Marshal(data)
	if err != nil {
		return err
	}
	defer clear(plain)
	ciphertext, err := secure.EncryptVault(plain, recipient)
	if err != nil {
		return err
	}
	return atomicWrite(s.VaultPath(), ciphertext)
}

func (s *Store) ChangePassword(oldPassword, newPassword []byte) error {
	if len([]rune(string(newPassword))) < 12 {
		return errors.New("new master password must contain at least 12 characters")
	}
	if err := s.checkDir(); err != nil {
		return err
	}
	encID, err := readSecure(s.IdentityPath(), 4<<20)
	if err != nil {
		return errors.New("reading identity failed")
	}
	id, err := secure.DecryptIdentity(encID, oldPassword)
	if err != nil {
		return err
	}
	enc, err := secure.EncryptIdentity(id, newPassword)
	if err != nil {
		return err
	}
	return atomicWrite(s.IdentityPath(), enc)
}

func (s *Store) Ciphertexts() ([]byte, []byte, error) {
	identity, err := readSecure(s.IdentityPath(), 4<<20)
	if err != nil {
		return nil, nil, err
	}
	vaultData, err := readSecure(s.VaultPath(), 64<<20)
	if err != nil {
		return nil, nil, err
	}
	return identity, vaultData, nil
}

func (s *Store) ValidateCiphertexts(identityData, vaultData, password []byte) error {
	id, err := secure.DecryptIdentity(identityData, password)
	if err != nil {
		return err
	}
	plain, err := secure.DecryptVault(vaultData, id)
	if err != nil {
		return errors.New("backup vault authentication failed")
	}
	defer clear(plain)
	var data vault.Data
	if err := json.Unmarshal(plain, &data); err != nil || data.Version != vault.FormatVersion {
		return errors.New("unsupported backup vault")
	}
	return nil
}

func (s *Store) ReplaceCiphertexts(identityData, vaultData []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// #nosec G302 -- directories require execute permission; 0700 is owner-only.
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return err
	}
	oldIdentity, _ := os.ReadFile(s.IdentityPath())
	oldVault, _ := os.ReadFile(s.VaultPath())
	if err := atomicWrite(s.IdentityPath(), identityData); err != nil {
		return err
	}
	if err := atomicWrite(s.VaultPath(), vaultData); err != nil {
		if len(oldIdentity) > 0 {
			_ = atomicWrite(s.IdentityPath(), oldIdentity)
		}
		if len(oldVault) > 0 {
			_ = atomicWrite(s.VaultPath(), oldVault)
		}
		return err
	}
	return nil
}

func (s *Store) checkDir() error {
	info, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	if !ok || uid < 0 || uint64(stat.Uid) != uint64(uid) || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("data directory must be owner-only (0700)")
	}
	return nil
}

func readSecure(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret file must be a regular owner-only file")
	}
	f, err := os.Open(path) // #nosec G304 -- path is one of the store's fixed internal filenames.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return b, nil
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".passman-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- dir is the parent of a fixed internal store path.
	if err == nil {
		defer func() { _ = d.Close() }()
		_ = d.Sync()
	}
	return nil
}
