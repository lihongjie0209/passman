package secure

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

func NewIdentity() (*age.X25519Identity, error) { return age.GenerateX25519Identity() }

func EncryptIdentity(identity *age.X25519Identity, password []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(string(password))
	if err != nil {
		return nil, fmt.Errorf("creating password recipient: %w", err)
	}
	return encrypt([]byte(identity.String()+"\n"), recipient)
}

func DecryptIdentity(ciphertext, password []byte) (*age.X25519Identity, error) {
	identity, err := age.NewScryptIdentity(string(password))
	if err != nil {
		return nil, errors.New("invalid master password")
	}
	plain, err := decrypt(ciphertext, identity)
	if err != nil {
		return nil, errors.New("invalid master password or damaged identity")
	}
	parsed, err := age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	clear(plain)
	if err != nil {
		return nil, errors.New("damaged identity")
	}
	return parsed, nil
}

func EncryptVault(plain []byte, recipient age.Recipient) ([]byte, error) {
	return encrypt(plain, recipient)
}
func DecryptVault(ciphertext []byte, identity age.Identity) ([]byte, error) {
	return decrypt(ciphertext, identity)
}

func encrypt(plain []byte, recipient age.Recipient) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, fmt.Errorf("starting encryption: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finishing encryption: %w", err)
	}
	return out.Bytes(), nil
}

func decrypt(ciphertext []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(r, 64<<20+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > 64<<20 {
		clear(plain)
		return nil, errors.New("decrypted data exceeds limit")
	}
	return plain, nil
}
